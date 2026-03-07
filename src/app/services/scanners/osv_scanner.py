"""OSV-Scanner for multi-language dependency vulnerability detection."""
import json
import subprocess
import logging
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult

logger = logging.getLogger(__name__)


class OSVScanner(BaseScanner):
    """Scanner for multi-language dependency vulnerabilities using Google's osv-scanner."""
    
    # Files that trigger OSV-Scanner
    DEPENDENCY_FILES = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "Cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "mix.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile"
    ]
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "osv-scanner"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository contains supported dependency lock files.
        """
        for dep_file in self.DEPENDENCY_FILES:
            if next(repo_path.rglob(dep_file), None):
                return True
        return False
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run osv-scanner on repository.
        """
        results = []
        
        try:
            # Run osv-scanner with JSON output
            # We scan the entire directory recursively
            cmd = [
                "osv-scanner",
                "--json",
                "-r", str(repo_path)
            ]
            
            # osv-scanner exits with code 1 if vulnerabilities are found
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if not result.stdout:
                return results

            data = json.loads(result.stdout)
            found_count = sum(len(p.get("vulnerabilities", [])) for r in data.get("results", []) for p in r.get("packages", []))
            logger.info(f"OSV-Scanner found {found_count} vulnerabilities.")
            
            # OSV output structure can be complex, iterating through results
            for res in data.get("results", []):
                source = res.get("source", {})
                file_path = source.get("path", "")
                
                # Make path relative
                if file_path.startswith(str(repo_path)):
                    file_path = file_path[len(str(repo_path)) + 1:]
                
                # Exclude findings from env and .env directories
                if "env/" in file_path or ".env/" in file_path or file_path.startswith("env/") or file_path.startswith(".env/"):
                    continue
                
                for pkg_info in res.get("packages", []):
                    package = pkg_info.get("package", {})
                    pkg_name = package.get("name", "unknown")
                    pkg_version = package.get("version", "unknown")
                    pkg_ecosystem = package.get("ecosystem", "unknown")
                    
                    for vuln in pkg_info.get("vulnerabilities", []):
                        vuln_id = vuln.get("id", "Unknown ID")
                        summary = vuln.get("summary", vuln.get("details", "Dependency vulnerability"))
                        
                        # Extract aliases (CVEs)
                        aliases = vuln.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                        
                        scanner_result = ScannerResult(
                            title=f"Vulnerable {pkg_ecosystem} dependency: {pkg_name}",
                            severity="HIGH",  # OSV doesn't always provide a simple severity string in short output
                            description=summary,
                            scanner_name=self.get_name(),
                            file_path=file_path,
                            remediation=f"Update {pkg_name} to a version without {vuln_id}.",
                            cve_id=cve_id,
                            metadata={
                                "package": pkg_name,
                                "version": pkg_version,
                                "ecosystem": pkg_ecosystem,
                                "vuln_id": vuln_id,
                                "aliases": aliases
                            }
                        )
                        results.append(scanner_result)
                        
        except subprocess.TimeoutExpired:
            raise Exception("osv-scanner timed out")
        except Exception as e:
            # If osv-scanner is not installed or fails, we report it
            logger.error(f"osv-scanner execution error: {e}")
            
        return results
