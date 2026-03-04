"""npm-audit scanner for Node.js dependency vulnerability detection."""
import json
import subprocess
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult


class NpmAuditScanner(BaseScanner):
    """Scanner for Node.js dependency vulnerabilities using npm audit."""
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "npm-audit"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository has Node.js dependency files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if package.json or package-lock.json found
        """
        dependency_files = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml"
        ]
        
        for dep_file in dependency_files:
            if (repo_path / dep_file).exists():
                return True
        
        return False
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run npm audit scanner on Node.js dependencies.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            Exception: If npm audit fails
        """
        results = []
        
        # Check if project has a package.json first
        if not (repo_path / "package.json").exists():
            return results
            
        try:
            # First, install dependencies without modifying lock files if package.json exists
            # We use --package-lock-only to avoid downloading all packages if possible
            # or simply run npm install if there's no package-lock.json
            if not (repo_path / "package-lock.json").exists():
                subprocess.run(
                    ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                    capture_output=True,
                    timeout=120,
                    cwd=str(repo_path)
                )

            # Run npm audit with JSON output
            cmd = [
                "npm",
                "audit",
                "--json"
            ]
            
            # npm audit exits with non-zero if vulnerabilities found
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(repo_path)
            )
            
            # Parse JSON output
            if result.stdout:
                # Sometimes npm audit prints warnings before JSON
                # Find the first { to start parsing JSON
                stdout_text = result.stdout
                try:
                    start_idx = stdout_text.index('{')
                    json_str = stdout_text[start_idx:]
                    data = json.loads(json_str)
                except (ValueError, json.JSONDecodeError):
                    # Try to parse the whole stdout just in case
                    data = json.loads(stdout_text)
                    
                audit_report_version = data.get("auditReportVersion", 1)
                
                if audit_report_version >= 2:
                    results = self._parse_v2_format(data, repo_path)
                else:
                    results = self._parse_v1_format(data, repo_path)
                    
                print(f"npm-audit found {len(results)} vulnerabilities.")
                
        except subprocess.TimeoutExpired:
            raise Exception(f"npm audit scan timed out after 300 seconds")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse npm audit output: {e}")
        except FileNotFoundError:
            raise Exception("npm not found. Please install Node.js and npm")
        except Exception as e:
            raise Exception(f"npm audit scan failed: {e}")
        
        return results

    def _parse_v2_format(self, data: dict, repo_path: Path) -> List[ScannerResult]:
        """Parse npm audit v2 JSON format."""
        results = []
        vulnerabilities = data.get("vulnerabilities", {})
        
        for pkg_name, pkg_data in vulnerabilities.items():
            severity = self._map_severity(pkg_data.get("severity", "moderate"))
            is_direct = pkg_data.get("isDirect", False)
            
            for via_item in pkg_data.get("via", []):
                # Only process string or standard dictionary entries that represent actual CVE mappings
                if isinstance(via_item, dict) and "source" in via_item:
                    cve_id = next((c for c in via_item.get("cves", []) if "CVE-" in c), None)
                    vibe_title = via_item.get("title", f"Vulnerability in {pkg_name}")
                    scanner_result = ScannerResult(
                        title=f"Vulnerable dependency: {pkg_name} ({vibe_title})",
                        severity=severity,
                        description=f"{pkg_name} has a known vulnerability: {vibe_title}. \nDetails: {via_item.get('url', '')}",
                        scanner_name=self.get_name(),
                        file_path="package-lock.json" if not is_direct else "package.json",
                        remediation=f"Run `npm audit fix` to automatically correct this vulnerability, or manually update `{pkg_name}`.",
                        cve_id=cve_id,
                        confidence="HIGH",
                        metadata={
                            "package": pkg_name,
                            "severity": pkg_data.get("severity"),
                            "is_direct": is_direct,
                            "url": via_item.get("url")
                        }
                    )
                    results.append(scanner_result)
        return results

    def _parse_v1_format(self, data: dict, repo_path: Path) -> List[ScannerResult]:
        """Parse older npm audit v1 JSON format (fallback)."""
        results = []
        advisories = data.get("advisories", {})
        
        for adv_id, advisory in advisories.items():
            pkg_name = advisory.get("module_name", "unknown")
            severity = self._map_severity(advisory.get("severity", "moderate"))
            cves = advisory.get("cves", [])
            cve_id = cves[0] if cves else None
            
            scanner_result = ScannerResult(
                title=f"Vulnerable dependency: {pkg_name} ({advisory.get('title', 'Unknown advisory')})",
                severity=severity,
                description=advisory.get("overview", f"{pkg_name} has a known vulnerability."),
                scanner_name=self.get_name(),
                file_path="package.json",
                remediation=advisory.get("recommendation", f"Update {pkg_name} to a secure version"),
                cve_id=cve_id,
                confidence="HIGH",
                metadata={
                    "package": pkg_name,
                    "advisory_url": advisory.get("url"),
                    "vulnerable_versions": advisory.get("vulnerable_versions"),
                    "patched_versions": advisory.get("patched_versions")
                }
            )
            results.append(scanner_result)
        return results

    def _map_severity(self, npm_severity: str) -> str:
        """Map npm severity (critical, high, moderate, low) to our standard (HIGH, MEDIUM, LOW)."""
        npm_severity = npm_severity.lower()
        if npm_severity in ["critical", "high"]:
            return "HIGH"
        elif npm_severity == "moderate":
            return "MEDIUM"
        else:
            return "LOW"
