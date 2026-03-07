"""pip-audit scanner for Python dependency vulnerability detection."""
import json
import subprocess
import logging
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult

logger = logging.getLogger(__name__)


class PipAuditScanner(BaseScanner):
    """Scanner for Python dependency vulnerabilities using pip-audit."""
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "pip-audit"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository has Python dependency files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if requirements.txt, setup.py, or pyproject.toml found
        """
        dependency_files = [
            "requirements.txt",
            "setup.py",
            "pyproject.toml",
            "Pipfile",
            "poetry.lock"
        ]
        
        for dep_file in dependency_files:
            if (repo_path / dep_file).exists():
                return True
        
        return False
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run pip-audit scanner on Python dependencies.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            subprocess.CalledProcessError: If pip-audit fails
        """
        results = []
        
        # Try to find dependency file
        dependency_file = self._find_dependency_file(repo_path)
        if not dependency_file:
            return results  # No dependency file found
        
        try:
            # Run pip-audit with JSON output
            cmd = [
                "pip-audit",
                "--format", "json",
                "--requirement", str(dependency_file)
            ]
            
            # pip-audit exits with code 1 if vulnerabilities found
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(repo_path)
            )
            
            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)
                found_count = sum(len(d.get("vulns", [])) for d in data.get("dependencies", []))
                logger.info(f"pip-audit found {found_count} vulnerabilities.")
                
                # Process each vulnerability
                for vuln in data.get("dependencies", []):
                    package_name = vuln.get("name", "unknown")
                    package_version = vuln.get("version", "unknown")
                    
                    for issue in vuln.get("vulns", []):
                        # Extract CVE IDs
                        cve_ids = issue.get("aliases", [])
                        cve_id = cve_ids[0] if cve_ids else issue.get("id")
                        
                        # Map CVSS score to severity
                        severity = self._map_cvss_to_severity(issue)
                        
                        # Get fixed versions
                        fixed_versions = issue.get("fix_versions", [])
                        remediation = self._build_remediation(
                            package_name,
                            package_version,
                            fixed_versions
                        )
                        
                        scanner_result = ScannerResult(
                            title=f"Vulnerable dependency: {package_name}",
                            severity=severity,
                            description=issue.get("description", f"{package_name} {package_version} has a known vulnerability"),
                            scanner_name=self.get_name(),
                            file_path=str(dependency_file.relative_to(repo_path)),
                            remediation=remediation,
                            cve_id=cve_id,
                            metadata={
                                "package": package_name,
                                "version": package_version,
                                "fixed_versions": fixed_versions,
                                "advisory_url": issue.get("advisory_url"),
                                "published": issue.get("published")
                            }
                        )
                        results.append(scanner_result)
        
        except subprocess.TimeoutExpired:
            raise Exception(f"pip-audit scan timed out after 300 seconds")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse pip-audit output: {e}")
        except FileNotFoundError:
            raise Exception("pip-audit not found. Please install it: pip install pip-audit")
        except Exception as e:
            raise Exception(f"pip-audit scan failed: {e}")
        
        return results
    
    def _find_dependency_file(self, repo_path: Path) -> Path:
        """
        Find the first available dependency file.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            Path to dependency file or None
        """
        # Priority order
        dependency_files = [
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile"
        ]
        
        for dep_file in dependency_files:
            # Efficiently search for dependency files but avoid env/.env
            # We use rglob but filter out matches in excluded directories
            for found_path in repo_path.rglob(dep_file):
                path_str = str(found_path.relative_to(repo_path))
                if not any(excluded in path_str for excluded in ["env/", ".env/", "venv/"]):
                    return found_path
        
        return None
    
    def _map_cvss_to_severity(self, issue: dict) -> str:
        """
        Map CVSS score to severity level.
        
        CVSS Scoring:
        - 9.0-10.0: CRITICAL -> HIGH
        - 7.0-8.9: HIGH -> HIGH
        - 4.0-6.9: MEDIUM -> MEDIUM
        - 0.1-3.9: LOW -> LOW
        
        Args:
            issue: Vulnerability issue dictionary
            
        Returns:
            Severity level (HIGH/MEDIUM/LOW)
        """
        # Try to get CVSS score from various fields
        cvss_score = None
        
        # Check for CVSS v3 score
        if "cvss" in issue and isinstance(issue["cvss"], dict):
            cvss_score = issue["cvss"].get("score")
        
        # Fallback to severity field if present
        if cvss_score is None and "severity" in issue:
            severity_str = issue["severity"].upper()
            if severity_str in ["CRITICAL", "HIGH"]:
                return "HIGH"
            elif severity_str == "MEDIUM":
                return "MEDIUM"
            elif severity_str == "LOW":
                return "LOW"
        
        # Map CVSS score to severity
        if cvss_score is not None:
            try:
                score = float(cvss_score)
                if score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            except (ValueError, TypeError):
                pass
        
        # Default to MEDIUM if unable to determine
        return "MEDIUM"
    
    def _build_remediation(
        self,
        package_name: str,
        current_version: str,
        fixed_versions: List[str]
    ) -> str:
        """
        Build remediation advice for vulnerable dependency.
        
        Args:
            package_name: Name of vulnerable package
            current_version: Current installed version
            fixed_versions: List of versions that fix the vulnerability
            
        Returns:
            Remediation string
        """
        if fixed_versions:
            # Get the latest fixed version
            latest_fix = fixed_versions[-1] if fixed_versions else "latest"
            return (
                f"Update {package_name} from {current_version} to {latest_fix} or later. "
                f"Run: pip install --upgrade '{package_name}>={latest_fix}'"
            )
        else:
            return (
                f"No fixed version available for {package_name}. "
                f"Consider using an alternative package or waiting for a security patch."
            )
