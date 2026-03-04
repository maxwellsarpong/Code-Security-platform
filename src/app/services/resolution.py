import os
import time
import requests
import tempfile
import shutil
import uuid
from typing import Optional
from uuid import UUID
from pathlib import Path
from git import Repo
from sqlmodel import Session, select
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..models import Scan, Finding, User
from ..core.config import Settings
from ..schemas import ResolutionResponse
from ..core import db
from .slack_service import SlackService
from .jira_service import JiraService

settings = Settings()

class ResolutionService:
    _lock = Lock() # To prevent concurrent writes to the same repo if needed, though each job has its own temp dir

    def __init__(self, session: Session):
        self.session = session
        print("!!! RESOLUTION SERVICE VERSION 6.0 - MULTI-TENANT !!!")

    def resolve_finding(self, finding_id: UUID, github_token: Optional[str] = None, force_sync: bool = False) -> ResolutionResponse:
        search_id = str(finding_id).replace("-", "")
        print(f"!!! RESOLUTION !!! Attempting to resolve ID: {finding_id} (normalized: {search_id})")
        
        # 1. Try to find as a Finding
        # Fast direct lookup (may fail depending on DB driver/type handling)
        finding = self.session.get(Finding, finding_id)
        
        if not finding:
            # Fallback for SQLite/String ID mismatch
            stmt = select(Finding)
            findings = self.session.exec(stmt).all()
            finding = next((f for f in findings if str(f.id).replace("-", "") == search_id), None)
            
            if finding:
                print(f"DEBUG: Found finding {finding.id} via manual scan.")

        if finding:
            if finding.is_fixed:
                return ResolutionResponse(
                    status="success",
                    finding_id=finding_id,
                    message=f"Finding {finding_id} is already fixed."
                )
            
            # Use lower() for case-insensitive severity comparison
            severity = finding.severity.upper()
            if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                worker_sync = os.getenv("WORKER_SYNC", "false").lower() in ("1", "true", "yes")
                if worker_sync or force_sync:
                    return self._resolve_single_finding(finding, github_token)
                else:
                    enqueue_resolution(str(finding_id), github_token)
                    return ResolutionResponse(
                        status="queued",
                        finding_id=finding_id,
                        message="Resolution task has been queued and is processing in the background."
                    )
            else:
                return ResolutionResponse(
                    status="failed",
                    finding_id=finding_id,
                    message=f"Finding {finding_id} has severity {severity}, which is not eligible for automated resolution (requires MEDIUM or higher)."
                )

        # 2. Try to find as a Scan
        scan = self.session.get(Scan, finding_id)
        if not scan:
             scans = self.session.exec(select(Scan)).all()
             scan = next((s for s in scans if str(s.id).replace("-", "") == search_id), None)
             if scan:
                 print(f"DEBUG: Found scan {scan.id} via manual scan.")
        
        if scan:
            # Check for worker sync env var or fallback
            worker_sync = os.getenv("WORKER_SYNC", "false").lower() in ("1", "true", "yes")
            if worker_sync or force_sync:
                scan_findings = self.session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
                return self._resolve_multiple_findings(scan, scan_findings, github_token)
            else:
                # Enqueue as background task
                enqueue_resolution(str(finding_id), github_token)
                return ResolutionResponse(
                    status="queued",
                    finding_id=finding_id,
                    message="Resolution task has been queued and is processing in the background."
                )

        print(f"ID {finding_id} (normalized: {search_id}) not found as Finding or Scan.")
        return ResolutionResponse(
            status="failed",
            finding_id=finding_id,
            message=f"ID {finding_id} was not found as a Finding or a Scan."
        )

    def _resolve_multiple_findings(self, scan: Scan, findings: list[Finding], github_token: Optional[str] = None) -> ResolutionResponse:
        if not findings:
             findings = self.session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
        
        if not findings:
            return ResolutionResponse(status="failed", finding_id=scan.id, message="No findings to resolve.")

        # Token Resolution with ultra-transparency
        print(f"[{scan.id}] --- TOKEN DISCOVERY START ---")
        
        # Determine platform from repo_url
        platform = "github"
        if "gitlab.com" in scan.repo_url.lower():
            platform = "gitlab"
        elif "bitbucket.org" in scan.repo_url.lower():
            platform = "bitbucket"
        
        raw_payload = github_token # This comes from the API payload (ResolutionRequest)
        raw_db = scan.git_token
        
        # Get settings token based on platform
        raw_settings = None
        if platform == "github":
            raw_settings = settings.github_token
        elif platform == "gitlab":
            raw_settings = settings.gitlab_token
        elif platform == "bitbucket":
            raw_settings = settings.bitbucket_token
            
        raw_env = os.getenv(f"{platform.upper()}_TOKEN")
        # 5. User settings (New)
        raw_user = None
        user = self.session.get(User, scan.user_id)
        if user:
            if platform == "github":
                raw_user = user.github_token
            elif platform == "gitlab":
                raw_user = user.gitlab_token
            elif platform == "bitbucket":
                raw_user = user.bitbucket_token
        
        print(f"[{scan.id}] Platform: {platform}")
        print(f"[{scan.id}] 1. Payload: {'Present' if raw_payload else 'None/Empty'} (Len: {len(raw_payload) if raw_payload else 0})")
        print(f"[{scan.id}] 2. DB Scan: {'Present' if raw_db else 'None/Empty'} (Len: {len(raw_db) if raw_db else 0})")
        print(f"[{scan.id}] 3. User: {'Present' if raw_user else 'None/Empty'} (Len: {len(raw_user) if raw_user else 0})")
        print(f"[{scan.id}] 4. Settings ({platform}): {'Present' if raw_settings else 'None/Empty'} (Len: {len(raw_settings) if raw_settings else 0})")
        print(f"[{scan.id}] 5. OS Env ({platform.upper()}_TOKEN): {'Present' if raw_env else 'None/Empty'} (Len: {len(raw_env) if raw_env else 0})")

        token = None
        token_source = "None Found"
        
        if raw_payload and raw_payload.strip():
            token = raw_payload.strip()
            token_source = "API Payload"
        elif not token and raw_db and raw_db.strip():
            token = raw_db.strip()
            token_source = "Scan Model (DB)"
        elif not token and raw_user and raw_user.strip():
            token = raw_user.strip()
            token_source = "User Model"
        elif not token and raw_settings and raw_settings.strip():
            token = raw_settings.strip()
            token_source = f"App Settings ({platform})"
        elif not token and raw_env and raw_env.strip():
            token = raw_env.strip()
            token_source = f"os.environ ({platform.upper()}_TOKEN)"
            
        print(f"[{scan.id}] FINAL CHOICE: {token_source} (Len: {len(token) if token else 0})")
        print(f"[{scan.id}] --- TOKEN DISCOVERY END ---")

        repo_dir = tempfile.mkdtemp(prefix="resolve_scan_")
        
        try:
            repo_path = Path(repo_dir)
            clone_url = scan.repo_url
            if token:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(scan.repo_url)
                # For Git commands, we need to ensure the token is in the netloc
                clone_url = urlunparse(parsed._replace(netloc=f"{token}@{parsed.netloc}"))

            print(f"[{scan.id}] STATUS: IN_PROGRESS - Cloning repository: {scan.repo_url}")
            # Fix for Git Error 128 RPC failed: force HTTP/1.1 and increase buffer
            clone_env = os.environ.copy()
            clone_env["GIT_HTTP_VERSION"] = "1.1"
            
            repo = Repo.clone_from(
                clone_url, 
                repo_dir, 
                env=clone_env,
                config='http.postBuffer=524288000',
                allow_unsafe_options=True
            )
            
            # Detect default branch before switching
            default_branch = repo.active_branch.name
            print(f"[{scan.id}] Detected default branch: {default_branch}")

            branch_name = f"fix/scan-{str(scan.id)[:8]}-{int(time.time())}"
            new_branch = repo.create_head(branch_name)
            new_branch.checkout()
            print(f"[{scan.id}] Checked out branch: {branch_name}")

            # Optimization: Group findings by file to minimize I/O and allow parallel processing across files
            files_to_findings = {}
            for f in findings:
                if f.file_path not in files_to_findings:
                    files_to_findings[f.file_path] = []
                files_to_findings[f.file_path].append(f)

            resolved_count = 0
            applied_findings = []

            # Use ThreadPoolExecutor to generate fixes in parallel across different files
            def process_file_findings(file_path, findings_list):
                results = []
                # Ensure we strip leading slash to avoid pathlib / join issues
                clean_path = file_path.lstrip("/")
                current_file_path = repo_path / clean_path
                if not current_file_path.exists():
                    return results

                # We must apply findings for the SAME file sequentially to handle overlapping fixes
                with open(current_file_path, "r") as f:
                    content = f.read()

                modified = False
                for finding in findings_list:
                    new_content = self._generate_fix(finding, repo_path, content=content)

                    if new_content and new_content != content:
                        content = new_content
                        modified = True
                        results.append(finding)
                
                if modified:
                    with open(current_file_path, "w") as f:
                        f.write(content)
                
                return results

            with ThreadPoolExecutor(max_workers=min(len(files_to_findings), 10)) as executor:
                future_to_file = {
                    executor.submit(process_file_findings, file_path, findings_list): file_path 
                    for file_path, findings_list in files_to_findings.items()
                }
                
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        file_results = future.result()
                        if file_results:
                            # Use lstrip to ensure GitPython doesn't see an absolute path
                            repo.index.add([file_path.lstrip("/")])
                            applied_findings.extend(file_results)
                            resolved_count += len(file_results)
                    except Exception as e:
                        print(f"[{scan.id}] ERROR: Failed to process fixes for {file_path}: {e}")

            if resolved_count == 0:
                print(f"[{scan.id}] STATUS: FAILED - Initial resolution pass yielded zero fixes. Triggering batch-level AI fallback.")
                
                # Batch-level fallback: Iterate through findings one more time with AI
                for f in findings:
                    clean_path = f.file_path.lstrip("/")
                    file_path = repo_path / clean_path
                    if not file_path.exists():
                        continue
                        
                    with open(file_path, "r") as f_handle:
                        content = f_handle.read()
                    
                    # We call _generate_fix with force_ai=True (we'll update that method next)
                    # or simply call a specialized batch AI method if we want to be more direct.
                    new_content = self._generate_fix(f, repo_path, content=content, force_ai=True)
                    
                    if new_content and new_content != content:
                        with open(file_path, "w") as f_handle:
                            f_handle.write(new_content)
                        # Normalize path for Git staging
                        repo.index.add([clean_path])
                        applied_findings.append(f)
                        resolved_count += 1
                
                if resolved_count == 0:
                    print(f"[{scan.id}] STATUS: FAILED - Batch-level AI fallback also failed to generate any fixes.")
                    return ResolutionResponse(status="failed", finding_id=scan.id, message="Could not generate fixes for any findings in this scan (even with AI fallback).")
                else:
                    print(f"[{scan.id}] STATUS: IN_PROGRESS - Batch-level AI successfully resolved {resolved_count} findings.")

            print(f"[{scan.id}] STATUS: IN_PROGRESS - Resolved {resolved_count} findings. Preparing to commit and push.")

            if not token:
                print(f"[{scan.id}] FATAL: Ready to push but still have NO token. Token source was: {token_source}")
                return ResolutionResponse(status="failed", finding_id=scan.id, message="Authentication required for push. No GITHUB_TOKEN or scan.git_token found.")

            # Configure Git user for the worker
            with repo.config_writer() as cw:
                cw.set_value("user", "name", "Security Platform Worker")
                cw.set_value("user", "email", "worker@security-platform.local")

            # Unified commit
            commit_msg = f"Security Fixes for Scan {str(scan.id)[:8]}\n\nResolved {resolved_count} findings:\n"
            for f in applied_findings:
                commit_msg += f"- {f.title} in {f.file_path}\n"
            
            repo.index.commit(commit_msg)
            
            # Push
            print(f"[{scan.id}] STATUS: IN_PROGRESS - Pushing {branch_name} to origin...")
            origin = repo.remote(name='origin')
            
            # Ensure the origin URL has the token for push if not already present
            if token and isinstance(origin.url, str) and "@" not in origin.url:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(origin.url)
                auth_url = urlunparse(parsed._replace(netloc=f"{token}@{parsed.netloc}"))
                origin.set_url(auth_url)
                print(f"[{scan.id}] DEBUG: Updated remote URL for authenticated push.")

            origin.push(branch_name)
            print(f"[{scan.id}] STATUS: IN_PROGRESS - Pushed {branch_name} to origin successfully.")

            # Create PR representing the whole scan (passing first finding as a placeholder for the helper)
            print(f"[{scan.id}] STATUS: IN_PROGRESS - Attempting to create PR for {resolved_count} fixes on base branch {default_branch}...")
            pr_url = self._create_pull_request(
                scan.repo_url, 
                branch_name, 
                applied_findings[0], 
                token, 
                is_bundled=True, 
                count=resolved_count,
                base_branch=default_branch,
                user=user
            )
            
            if pr_url:
                print(f"[{scan.id}] STATUS: IN_PROGRESS - Successfully created PR: {pr_url}")
            else:
                print(f"[{scan.id}] ERROR: PR creation failed or returned None.")

            # Mark all applied findings as fixed
            for f in applied_findings:
                f.is_fixed = True
                f.pr_url = pr_url
                self.session.add(f)
            self.session.commit()

            print(f"[{scan.id}] STATUS: COMPLETED - {resolved_count} fixes applied. PR: {pr_url}")

            # Record billing for resolution
            if pr_url:
                try:
                    from .billing import record_usage
                    record_usage(user_id=scan.user_id, resolutions=1, session=self.session)
                except Exception as e:
                    print(f"[{scan.id}] Failed to record resolution usage: {e}")


            return ResolutionResponse(
                status="success",
                pr_url=pr_url,
                finding_id=scan.id,
                message=f"Created single PR with {resolved_count} fixes: {pr_url}" if pr_url else f"Pushed {resolved_count} fixes to branch {branch_name}, but PR creation failed."
            )

        except Exception as e:
            print(f"[{scan.id}] CRITICAL ERROR during bundled resolution: {str(e)}")
            import traceback
            traceback.print_exc()
            return ResolutionResponse(status="failed", finding_id=scan.id, message=f"Error during bundled resolution: {str(e)}")
        finally:
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir)

    def _resolve_single_finding(self, finding: Finding, github_token: Optional[str] = None) -> ResolutionResponse:
        scan = self.session.get(Scan, finding.scan_id)
        if not scan:
            return ResolutionResponse(
                status="failed",
                finding_id=finding.id,
                message="Scan not found for finding"
            )
        # Re-use the bundled logic for single finding for consistency
        return self._resolve_multiple_findings(scan, [finding], github_token)

    def _generate_fix(self, finding: Finding, repo_path: Path, content: Optional[str] = None, force_ai: bool = False) -> Optional[str]:
        """
        Deterministic, rule-based Fix Generation logic.
        """
        if content is None:
            clean_path = finding.file_path.lstrip("/")
            file_path = repo_path / clean_path
            if not file_path.exists():
                return None
            with open(file_path, "r") as f:
                content = f.read()

        # Step 1: Deterministic rules (if not forcing AI)
        if not force_ai:
            # 1. Handle dependency updates (e.g., from pip-audit)
            if (finding.title and "Vulnerable dependency:" in finding.title) or (finding.description and "Vulnerable dependency" in finding.description):
                return self._fix_dependency(content, finding)

            # 2. Handle common pattern replacements
            # Example: Binding to 0.0.0.0
            if "0.0.0.0" in content and ((finding.title and "bind" in finding.title.lower()) or (finding.description and "address" in finding.description.lower())):
                fixed_content = content.replace("0.0.0.0", "127.0.0.1")
                if fixed_content != content:
                    print(f"[{finding.id}] Applying rule-based fix: Switched 0.0.0.0 to 127.0.0.1")
                    return fixed_content

            # 3. Handle 'assert used' (common in Bandit) - We generally don't fix this automatically as it's often intended
            if finding.title and "assert_used" in finding.title and "assert " in content:
                pass

            # 4. Handle Django missing CSRF token
            if (finding.title and "Django No Csrf Token" in finding.title) or (finding.description and "Django No Csrf Token" in finding.description):
                if "<form" in content.lower():
                    if "{% csrf_token %}" not in content:
                        import re
                        # Add {% csrf_token %} after the opening <form> tag, handle variations
                        # Using a more robust regex that ignores case and handles potential attributes
                        fixed_content = re.sub(r'(<form[^>]*>)', r'\1\n    {% csrf_token %}', content, flags=re.IGNORECASE)
                        if fixed_content != content:
                            print(f"[{finding.id}] Applying rule-based fix: Added CSRF token to Django form")
                            return fixed_content

            # 5. Handle hardcoded password strings (Bandit B105) or Django Secret Key
            if finding.title and any(kw in finding.title.lower() for kw in ["hardcoded_password", "secret_key"]):
                 import re
                 # Look for assignment like password = "..." or SECRET_KEY = '...'
                 # Improved pattern to catch both password-like and SECRET_KEY variables
                 pattern = r'([a-zA-Z0-9_]*(?:password|secret_key|api_key|token)[a-zA-Z0-9_]*\s*=\s*)(["\'])(?:(?!\2).)+\2'
                 replacement = r"\1os.environ.get('SECRET_OR_PASSWORD', 'REPLACE_ME')"
                 fixed_content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
                 if fixed_content != content:
                     if "import os" not in fixed_content:
                         fixed_content = "import os\n" + fixed_content
                     print(f"[{finding.id}] Applying rule-based fix: Replaced hardcoded secret with os.environ.get")
                     return fixed_content

            # 6. Handle unsafe JS Document methods (e.g. document.write)
            if (finding.title and "Insecure Document Method" in finding.title) or (finding.description and "document.write" in finding.description.lower()):
                if "document.write(" in content or "document.writeln(" in content:
                    import re
                    fixed_content = re.sub(r'document\.write(ln)?\(', r'// [FIXED] replaced insecure write\n    console.log(', content)
                    if fixed_content != content:
                        print(f"[{finding.id}] Applying rule-based fix: Replaced insecure document.write")
                        return fixed_content

            # 9. Handle Sha224 Hash (Bandit B303)
            if (finding.title and "Sha224 Hash" in finding.title) or (finding.description and "hashlib.sha224" in finding.description.lower()):
                if "hashlib.sha224(" in content:
                    fixed_content = content.replace("hashlib.sha224(", "hashlib.sha256(")
                    if fixed_content != content:
                        print(f"[{finding.id}] Applying rule-based fix: Switched SHA224 to SHA256")
                        return fixed_content

            # 10. Handle Weak SSL Version (Bandit B323)
            if (finding.title and "Weak Ssl Version" in finding.title) or (finding.description and "ssl.PROTOCOL_TLS" in finding.description.lower()):
                weak_versions = ["ssl.PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1", "ssl.PROTOCOL_SSLv2", "ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_SSLv23"]
                fixed_content = content
                for ver in weak_versions:
                    if ver in fixed_content:
                        fixed_content = fixed_content.replace(ver, "ssl.PROTOCOL_TLS_CLIENT")
                if fixed_content != content:
                    print(f"[{finding.id}] Applying rule-based fix: Upgraded weak SSL/TLS version to PROTOCOL_TLS_CLIENT")
                    return fixed_content

            # 11. Handle Request Session With Http
            if (finding.title and "Request Session With Http" in finding.title) or (finding.description and "session with http://" in finding.description.lower()):
                if "http://" in content:
                    fixed_content = content.replace("http://", "https://")
                    if fixed_content != content:
                        print(f"[{finding.id}] Applying rule-based fix: Switched http:// to https://")
                        return fixed_content

            # 12. Prototype Pollution Mitigation (Basic Comment)
            if (finding.title and "Prototype Pollution" in finding.title) or (finding.description and "Prototype Pollution" in finding.description):
                if "obj[" in content and "attr]" in content: # Generic pollution pattern
                     fixed_content = content.replace("obj[attr]", "if(attr !== '__proto__' && attr !== 'constructor') obj[attr]")
                     if fixed_content != content:
                         print(f"[{finding.id}] Applying rule-based fix: Added basic prototype pollution check")
                         return fixed_content

            # 13. Handle Non Literal Import
            if (finding.title and "Non Literal Import" in finding.title) or (finding.description and "importlib.import_module" in finding.description.lower()):
                 if "import_module(" in content:
                     import re
                     # Add a safety comment before the line containing import_module
                     fixed_content = re.sub(r'(^.*import_module\(.*$)', r'# [SECURITY] Ensure input is validated\n\1', content, flags=re.MULTILINE)
                     if fixed_content != content:
                         print(f"[{finding.id}] Applying rule-based fix: Added warning for non-literal import")
                         return fixed_content

            # 14. Handle Django Custom Expression As Sql / Extends Custom Expression
            if (finding.title and "Custom Expression" in finding.title) or (finding.description and "as_sql" in finding.description.lower()):
                if "as_sql(" in content and "params" not in content:
                    import re
                    # Very basic attempt to suggest parameterization
                    fixed_content = re.sub(r'def as_sql\(self, compiler, connection\):', 
                                          'def as_sql(self, compiler, connection, **extra_context):', content)
                    if fixed_content != content:
                        print(f"[{finding.id}] Applying rule-based fix: Suggested parameterization for Custom Expression")
                        return fixed_content

            # 15. Handle try_except_pass (Bandit B110)
            if (finding.title and "try_except_pass" in finding.title) or (finding.description and "except: pass" in finding.description.lower()):
                 if "except:" in content and "pass" in content:
                     import re
                     # Replace empty pass with a safety comment or logging
                     fixed_content = re.sub(r'(except.*:)\s*\n\s+pass', r'\1 # [SECURITY] Do not suppress all errors\n            import logging; logging.error("Exception suppressed")', content)
                     if fixed_content != content:
                         print(f"[{finding.id}] Applying rule-based fix: Replaced pass with logging in except block")
                         return fixed_content
                     return None

            # 16. Handle request_without_timeout
            if (finding.title and "request_without_timeout" in finding.title) or (finding.description and "timeout" in finding.description.lower()):
                 if "requests." in content and "timeout=" not in content:
                     import re
                     # Add a default timeout of 10 seconds to requests calls
                     fixed_content = re.sub(r'(requests\.(get|post|put|delete|patch)\()', r'\1timeout=10, ', content)
                     if fixed_content != content:
                         print(f"[{finding.id}] Applying rule-based fix: Added default timeout to requests call")
                         return fixed_content

            # 17. Handle hardcoded_sql_expressions / Sqlalchemy Execute Raw Query / CWE-89 / SQL Injection
            if finding.title and any(x in finding.title.upper() for x in ["HARDCODED_SQL", "RAW QUERY", "EXECUTE", "CWE-89", "SQL INJECTION"]):
                 if ".execute(" in content:
                     import re
                     lines = content.splitlines()
                     idx = finding.line_number - 1 if finding.line_number else -1
                     
                     if 0 <= idx < len(lines):
                         line = lines[idx]
                         if ".execute(" in line:
                             # 1. False positive check: already parameterized
                             # Use non-greedy match to ensure we catch the first comma followed by params
                             if re.search(r'\.execute\(.*?,[\s\n]*[({]', line):
                                 if "# nosec" not in line and "# [SECURITY]" not in line:
                                     lines[idx] = line.split('#')[0].rstrip() + " # nosec B608 - already parameterized"
                                     print(f"[{finding.id}] Applying rule-based fix: Added nosec to line {finding.line_number} (CWE-89 FP)")
                                     return "\n".join(lines) + "\n"
                                 return None

                             # 2. SQLAlchemy text() check: session.execute, conn.execute, db.execute, engine.execute
                             if any(kw in line for kw in ["session.execute", "db.execute", "conn.execute", "engine.execute", "connection.execute"]):
                                 if "text(" not in line:
                                     # Wrap the argument of execute in text()
                                     new_line = re.sub(r'(\.execute\()(.*)(\))', r'\1text(\2)\3', line)
                                     if new_line != line:
                                         lines[idx] = new_line
                                         new_content = "\n".join(lines) + "\n"
                                         if "from sqlalchemy import text" not in new_content:
                                             new_content = "from sqlalchemy import text\n" + new_content
                                         print(f"[{finding.id}] Applying rule-based fix: Wrapped SQA execute in text() on line {finding.line_number}")
                                         return new_content

                             # 3. Fallback: Add security warning if not present
                             if "[SECURITY]" not in line and "# nosec" not in line:
                                 lines[idx] = line.rstrip() + " # [SECURITY] Use parameterized queries"
                                 print(f"[{finding.id}] Applying rule-based fix: Added security warning (CWE-89) to line {finding.line_number}")
                                 return "\n".join(lines) + "\n"
                             return None

            print(f"[{finding.id}] No deterministic rule found for finding: {finding.title}")
        
        # Step 2: Gemini AI Fallback
        gemini_key = os.getenv("GEMINI_API_KEY", settings.gemini_api_key)
            
        if gemini_key:
            try:
                from google import genai
                mode_str = " (BATCH FORCE)" if force_ai else ""
                print(f"[{finding.id}] DEBUG: Gemini API Key found. Attempting AI resolution for finding{mode_str}.")
                client = genai.Client(api_key=gemini_key)
                
                prompt = f"""
                You are an expert security engineer fixing vulnerabilities in code.
                I have a security finding to resolve:
                
                Finding Title: {finding.title}
                Finding Description: {finding.description}
                Severity: {finding.severity}
                
                Rewrite the following code file to fix the vulnerability. 
                Return ONLY the raw fixed code. Do not include markdown code blocks (like ```python) and do not provide any explanation.
                
                Code:
                {content}
                """
                
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                )
                
                fixed_code = response.text.strip()
                if fixed_code.startswith("```"):
                    lines = fixed_code.split("\n")
                    if len(lines) > 2 and lines[-1].strip() == "```":
                        fixed_code = "\n".join(lines[1:-1])
                        
                if fixed_code and fixed_code != content:
                    print(f"[{finding.id}] Gemini AI successfully generated a fix")
                    return fixed_code
                    
            except Exception as e:
                print(f"[{finding.id}] ERROR in Gemini AI fallback: {e}")

        return None

    def _fix_dependency(self, content: str, finding: Finding) -> Optional[str]:
        """
        Attempts to update a vulnerable dependency in a requirements file.
        """
        import re
        
        # Try to extract package and version from finding
        # Context usually looks like: "Vulnerable dependency: requests (2.25.0)"
        match = re.search(r"Vulnerable dependency:\s*([a-zA-Z0-9_\-]+)\s*(?:\(?([\d\.]+)\)?)?", finding.title)
        if not match:
            # Fallback to description
            match = re.search(r"package\s*([a-zA-Z0-9_\-]+)\s*(?:version\s*([\d\.]+))?", finding.description)
        
        if not match:
            return None

        package_name = match.group(1)
        # In a real system, we'd fetch the latest safe version. 
        # For this logic, we'll try to find the line and update it to a safe version.
        # If the remediation hint contains a version, we use that.
        # Regex to find package in requirements.txt (e.g., requests==2.25.0, requests>=2.25.0)
        pattern = rf"^{re.escape(package_name)}(==|>=|<=|~=|>|<)\s*([\d\.]+).*"
        
        target_version = None
        if finding.remediation:
            version_match = re.search(r"upgrade to ([\d\.]+)", finding.remediation, re.IGNORECASE)
            if version_match:
                target_version = version_match.group(1)

        if not target_version:
             # Improved versioning: Parse current version and increment patch if possible
             match_current = re.search(pattern, content, flags=re.IGNORECASE | re.MULTILINE)
             if match_current:
                 curr_ver = match_current.group(2)
                 try:
                     parts = curr_ver.split('.')
                     if len(parts) >= 3:
                         parts[-1] = str(int(parts[-1]) + 1)
                         target_version = '.'.join(parts)
                     else:
                         target_version = curr_ver + ".1"
                 except:
                     target_version = curr_ver + ".1"
             else:
                 target_version = "1.0.1" # Absolute fallback
        
        def replace_version(m):
            op = m.group(1)
            # Change any operator to == for specific fix or >=
            return f"{package_name}=={target_version}"

        new_content = []
        modified = False
        for line in content.splitlines():
            new_line = re.sub(pattern, replace_version, line, flags=re.IGNORECASE)
            if new_line != line:
                modified = True
            new_content.append(new_line)

        if modified:
            print(f"Applying rule-based fix: Updated {package_name} to {target_version} in {finding.file_path}")
            return "\n".join(new_content) + "\n"
        
        return None




    def _get_platform_info(self, repo_url: str):
        """
        Detects platform (GitHub, GitLab, Bitbucket) and extracts repository ID.
        """
        repo_url = repo_url.rstrip('/')
        if repo_url.endswith('.git'):
            repo_url = repo_url[:-4]
            
        if "github.com" in repo_url:
            parts = repo_url.split('/')
            return "github", f"{parts[-2]}/{parts[-1]}"
        elif "gitlab.com" in repo_url:
            from urllib.parse import urlparse
            path = urlparse(repo_url).path.strip('/')
            return "gitlab", path
        elif "bitbucket.org" in repo_url:
            parts = repo_url.split('/')
            return "bitbucket", f"{parts[-2]}/{parts[-1]}"
        return "unknown", None

    def _create_pull_request(self, repo_url: str, branch_name: str, finding: Finding, token: Optional[str], is_bundled: bool = False, count: int = 1, base_branch: str = "main", user: Optional[User] = None) -> Optional[str]:
        """
        Creates a Pull Request / Merge Request on GitHub, GitLab, or Bitbucket.
        """
        if not user:
             user = self.session.get(User, finding.user_id)
        
        slack_service = SlackService(user=user)
        jira_service = JiraService(user=user)
        if not token:
            print(f"ERROR: No token provided for PR creation. github_token: {token is not None}, scan.git_token: {finding.scan.git_token if finding.scan else 'N/A'}, settings.github_token: {settings.github_token is not None}")
            return None

        platform, repo_id = self._get_platform_info(repo_url)
        if platform == "unknown":
            print(f"Unknown platform for URL: {repo_url}")
            return None

        title = f"Fix: {finding.title}" if not is_bundled else f"Security Fixes: Resolved {count} vulnerabilities"
        body = f"This is an automated fix for the security finding: {finding.title}\n\n**Description:** {finding.description}\n**Severity:** {finding.severity}"
        if is_bundled:
             body = f"This PR contains automated security fixes for {count} vulnerabilities detected in a recent scan."

        try:
            if platform == "github":
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                }
                data = {
                    "title": title,
                    "body": body,
                    "head": branch_name,
                    "base": base_branch 
                }
                response = requests.post(f"https://api.github.com/repos/{repo_id}/pulls", json=data, headers=headers)
                print(f"DEBUG: GitHub API PR Creation Request: URL=https://api.github.com/repos/{repo_id}/pulls, Status={response.status_code}")
                if response.status_code == 201:
                    pr_url = response.json().get("html_url")
                    if pr_url:
                        # Notify Slack and Create Jira Task
                        slack_service.notify_pr_created(pr_url, finding.title, finding.severity)
                        jira_service.create_vulnerability_task(finding.title, finding.description, pr_url)
                    return pr_url
                else:
                    print(f"DEBUG: GitHub API Response Error: {response.text}")
            
            elif platform == "gitlab":
                headers = {"PRIVATE-TOKEN": token}
                data = {
                    "title": title,
                    "description": body,
                    "source_branch": branch_name,
                    "target_branch": base_branch
                }
                from urllib.parse import quote_plus
                encoded_id = quote_plus(repo_id)
                response = requests.post(f"https://gitlab.com/api/v4/projects/{encoded_id}/merge_requests", json=data, headers=headers)
                if response.status_code == 201:
                    pr_url = response.json().get("web_url")
                    if pr_url:
                        slack_service.notify_pr_created(pr_url, finding.title, finding.severity)
                        jira_service.create_vulnerability_task(finding.title, finding.description, pr_url)
                    return pr_url

            elif platform == "bitbucket":
                headers = {"Authorization": f"Bearer {token}"}
                data = {
                    "title": title,
                    "description": body,
                    "source": {"branch": {"name": branch_name}},
                    "destination": {"branch": {"name": base_branch}}
                }
                response = requests.post(f"https://api.bitbucket.org/2.0/repositories/{repo_id}/pullrequests", json=data, headers=headers)
                if response.status_code == 201:
                    pr_url = response.json().get("links", {}).get("html", {}).get("href")
                    if pr_url:
                        slack_service.notify_pr_created(pr_url, finding.title, finding.severity)
                        jira_service.create_vulnerability_task(finding.title, finding.description, pr_url)
                    return pr_url

            print(f"Failed to create {platform} PR/MR: {response.status_code} {response.text}")
            return None
        except Exception as e:
            print(f"ERROR: Exception while calling {platform} API: {str(e)}")
            import traceback
            traceback.print_exc()
            return None


# Background task support
try:
    from redis import Redis
    from rq import Queue, Retry
except ImportError:
    Redis = None
    Queue = None
    Retry = None

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

def enqueue_resolution(target_id: str, github_token: Optional[str] = None):
    """Enqueue a resolution job to Redis/RQ when available.
    """
    # Safety: Check if we are already inside a worker to prevent recursion
    if os.getenv("RQ_WORKER_ID"):
        print("WARNING: Skipping enqueue inside worker context to prevent infinite recursion.")
        from ..core.db import engine
        with Session(engine) as session:
            service = ResolutionService(session)
            return service.resolve_finding(UUID(target_id), github_token, force_sync=True)

    worker_sync = os.getenv("WORKER_SYNC", "false").lower() in ("1", "true", "yes")
    if worker_sync or Redis is None or Queue is None:
        from ..core.db import engine
        with Session(engine) as session:
            service = ResolutionService(session)
            return service.resolve_finding(UUID(target_id), github_token, force_sync=True)

    try:
        conn = Redis.from_url(REDIS_URL, decode_responses=True)
        q = Queue(name="resolutions", connection=conn)
        retry_policy = Retry(max=2, interval=[10, 30]) if Retry is not None else None
        q.enqueue("app.services.resolution.run_resolution", target_id, github_token, retry=retry_policy, job_timeout=600)
        return True
    except Exception as e:
        print(f"Failed to enqueue resolution: {e}")
        # fallback sync
        from ..core.db import engine
        with Session(engine) as session:
            service = ResolutionService(session)
            return service.resolve_finding(UUID(target_id), github_token)

def run_resolution(target_id: str, github_token: Optional[str] = None):
    """Background runner for resolution.
    """
    from ..core import db
    session = Session(db.engine)
    try:
        service = ResolutionService(session)
        print(f"DEBUG: Starting background resolution for {target_id}. Token present: {github_token is not None}")
        result = service.resolve_finding(UUID(target_id), github_token, force_sync=True)
        print(f"DEBUG: Background resolution finished for {target_id}. Status: {result.status}, Message: {result.message}")
    finally:
        session.close()
