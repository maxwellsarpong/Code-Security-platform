import time
import random
import datetime
import os
import sentry_sdk
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlmodel import Session
from ..models import Scan, Finding
from ..core.config import Settings
from typing import Optional, Dict, Any

# optional imports for RQ/Redis — keep runtime-safe if packages aren't installed
try:
    from redis import Redis
    from rq import Queue, Retry
except Exception:  # pragma: no cover - optional in dev
    Redis = None
    Queue = None
    Retry = None

# prometheus metrics
from prometheus_client import Counter, Histogram

settings = Settings()
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
from ..core import db

# metrics
SCANS_ENQUEUED = Counter("scp_scans_enqueued_total", "Total scans enqueued")
SCANS_STARTED = Counter("scp_scans_started_total", "Total scans started")
SCANS_COMPLETED = Counter("scp_scans_completed_total", "Total scans completed")
SCANS_FAILED = Counter("scp_scans_failed_total", "Total scans failed")
SCAN_DURATION = Histogram("scp_scan_duration_seconds", "Scan run duration seconds")

# simple in-memory index for quick read (scaffold only)
_scan_index: Dict[str, Dict[str, Any]] = {}


def enqueue_scan(scan_id, user_id: Optional[str] = None):
    """Enqueue a scan job to Redis/RQ when available.
    Falls back to synchronous execution when WORKER_SYNC=true or Redis isn't available (useful for local/dev/CI).
    """
    SCANS_ENQUEUED.inc()
    worker_sync = os.getenv("WORKER_SYNC", "false").lower() in ("1", "true", "yes")
    if worker_sync or Redis is None or Queue is None:
        return schedule_scan(scan_id, user_id=user_id)

    try:
        conn = Redis.from_url(REDIS_URL, decode_responses=True)
        q = Queue(name="scans", connection=conn)
        # enqueue the function by import path so worker can import it
        retry_policy = Retry(max=3, interval=[10, 30, 60]) if Retry is not None else None
        q.enqueue("app.services.scanner.schedule_scan", scan_id, user_id, retry=retry_policy, job_timeout=1200)
        return True
    except Exception:
        # if enqueue fails, run sync as a best-effort fallback
        return schedule_scan(scan_id, user_id=user_id)


def _record_failure(exc):
    try:
        sentry_sdk.capture_exception(exc)
    except Exception:
        pass


@SCAN_DURATION.time()
def schedule_scan(scan_id, user_id: Optional[str] = None):
    """
    Execute a scan job with real security scanners.
    Clones repository, runs applicable scanners, aggregates findings.

    Args:
        scan_id: UUID of the scan
        user_id: Optional user ID for billing
    """
    SCANS_STARTED.inc()
    start_time = time.time()

    from ..core import db
    from .scanners import BanditScanner, PipAuditScanner, CheckovScanner, SemgrepScanner, OSVScanner, NpmAuditScanner, RetirejsScanner
    from git import Repo
    import tempfile
    import shutil
    from pathlib import Path

    session = Session(db.engine)
    scan = None
    repo_dir = None

    try:
        # Fetch scan from database
        scan = session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Update status
        scan.status = "running"
        session.add(scan)
        session.commit()
        session.refresh(scan)

        # Clone repository to temporary directory
        repo_dir = tempfile.mkdtemp(prefix="scan_")
        repo_path = Path(repo_dir)

        clone_url = scan.repo_url
        token = scan.git_token
        
        # If no token in DB, check settings based on platform
        if not token:
            platform = "github"
            if "gitlab.com" in scan.repo_url.lower():
                platform = "gitlab"
            elif "bitbucket.org" in scan.repo_url.lower():
                platform = "bitbucket"
            
            if platform == "github":
                token = settings.github_token
            elif platform == "gitlab":
                token = settings.gitlab_token
            elif platform == "bitbucket":
                token = settings.bitbucket_token

        if token:
            # Reconstruct URL with token: https://<token>@github.com/user/repo.git
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(scan.repo_url)
            clone_url = urlunparse(parsed._replace(netloc=f"{token}@{parsed.netloc}"))

        try:
            print(f"Cloning repository: {scan.repo_url}") # Log without token
            # Force HTTP/1.1 and larger buffer for stability on complex repos
            env = os.environ.copy()
            env["GIT_HTTP_LOW_SPEED_LIMIT"] = "0"
            env["GIT_HTTP_LOW_SPEED_TIME"] = "999999"
            
            Repo.clone_from(clone_url, repo_dir, depth=1, env=env)
        except Exception as e:
            # Redact token from error message if possible
            error_msg = str(e)
            if scan.git_token:
                error_msg = error_msg.replace(scan.git_token, "********")
            raise Exception(f"Failed to clone repository: {error_msg}")

        # Initialize scanners
        scanners = [
            SemgrepScanner(),  # Multi-language scanner (runs first for broad coverage)
            BanditScanner(),   # Python-specific
            PipAuditScanner(), # Python dependencies
            NpmAuditScanner(), # Node.js dependencies
            RetirejsScanner(), # Bundled JS Library dependencies (e.g. jQuery)
            CheckovScanner(),  # IaC
            OSVScanner()       # Multi-lang dependencies (JS, Go, Rust, etc.)
        ]

        # Run applicable scanners in parallel and collect findings
        all_findings = []
        
        def run_scanner(scanner_instance, path):
            if scanner_instance.is_applicable(path):
                print(f"[{scan_id}] Starting scanner: {scanner_instance.get_name()}")
                try:
                    results = scanner_instance.scan(path)
                    print(f"[{scan_id}] Scanner {scanner_instance.get_name()} completed. Found {len(results)} issues.")
                    return results
                except Exception as e:
                    print(f"[{scan_id}] Scanner {scanner_instance.get_name()} failed: {e}")
                    raise
            return []

        # Vertical Scaling: adjust parallelism via ENV (default 2 for stability)
        scan_parallelism = int(os.getenv("SCAN_PARALLELISM", "2"))
        
        with ThreadPoolExecutor(max_workers=scan_parallelism) as executor:
            future_to_scanner = {
                executor.submit(run_scanner, s, repo_path): s 
                for s in scanners
            }
            
            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    _record_failure(e)

        # Store findings in database
        print(f"Found {len(all_findings)} issues. Saving to database...")
        for finding_result in all_findings:
            finding = Finding(
                scan_id=scan.id,
                user_id=scan.user_id,
                title=finding_result.title,
                severity=finding_result.severity,
                description=finding_result.description,
                remediation=finding_result.remediation,
                scanner_name=finding_result.scanner_name,
                file_path=finding_result.file_path,
                line_number=finding_result.line_number,
                cve_id=finding_result.cve_id,
                confidence=finding_result.confidence
            )
            session.add(finding)

        # Calculate risk score based on findings
        risk_score = _calculate_risk_score(all_findings)

        # Mark scan as completed
        scan.status = "completed"
        scan.completed_at = datetime.datetime.utcnow()
        scan.risk_score = risk_score
        session.add(scan)
        session.flush()
        session.commit()

        print(f"Scan {scan_id} completed successfully with risk score {risk_score}. Done.")

        SCANS_COMPLETED.inc()
        duration = time.time() - start_time
        SCAN_DURATION.observe(duration)

        # Record billing
        if user_id:
            try:
                from .billing import record_usage  # local import to avoid cycle in tests
                record_usage(user_id=user_id, scans=1, billable_units=1)
            except Exception as e:
                _record_failure(e)

    except Exception as exc:
        SCANS_FAILED.inc()
        if scan:
            scan.status = "failed"
            session.add(scan)
            session.commit()
        _record_failure(exc)
        raise

    finally:
        session.close()
        # Clean up cloned repository
        if repo_dir and Path(repo_dir).exists():
            try:
                shutil.rmtree(repo_dir)
            except Exception as e:
                print(f"Failed to clean up repo directory: {e}")



def _calculate_risk_score(findings: list) -> float:
    """
    Calculate risk score based on findings severity.
    
    Args:
        findings: List of ScannerResult objects
        
    Returns:
        Risk score from 0.0 to 10.0
    """
    if not findings:
        return 0.0
    
    # Weight by severity
    severity_weights = {
        "HIGH": 10.0,
        "MEDIUM": 5.0,
        "LOW": 1.0
    }
    
    total_score = 0.0
    for finding in findings:
        weight = severity_weights.get(finding.severity, 1.0)
        total_score += weight
    
    # Normalize to 0-10 scale
    # Cap at 10 findings of HIGH severity = 10.0 score
    max_score = 100.0  # 10 HIGH findings
    normalized_score = min(10.0, (total_score / max_score) * 10.0)
    
    return round(normalized_score, 2)



def get_scan_result(scan_id) -> Optional[dict]:
    # Cache removed in favor of DB truth
    return None
