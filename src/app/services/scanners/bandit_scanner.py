"""Bandit scanner for Python static security analysis."""
import json
import subprocess
import logging
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult

logger = logging.getLogger(__name__)


class BanditScanner(BaseScanner):
    """Scanner for Python security issues using Bandit."""
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "bandit"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository contains Python files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if Python files are found
        """
        # Check for any .py files efficiently
        return next(repo_path.rglob("*.py"), None) is not None
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run Bandit scanner on Python code.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            subprocess.CalledProcessError: If Bandit fails
        """
        results = []
        
        try:
            # Run bandit with JSON output
            cmd = [
                "bandit",
                "-r",  # Recursive
                str(repo_path),
                "-f", "json",  # JSON format
                "-x", "env,.env", # Exclude virtual environments
                "--quiet"  # Suppress progress
            ]
            
            # Bandit exits with code 1 if issues found, which is expected
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)
                found_count = len(data.get("results", []))
                logger.info(f"Bandit found {found_count} issues.")
                
                # Process each finding
                for issue in data.get("results", []):
                    # Map Bandit severity to our levels
                    severity = self._map_bandit_severity(
                        issue.get("issue_severity", "MEDIUM"),
                        issue.get("issue_confidence", "MEDIUM")
                    )
                    
                    # Extract file path relative to repo
                    file_path = issue.get("filename", "")
                    if file_path.startswith(str(repo_path)):
                        file_path = file_path[len(str(repo_path)) + 1:]
                    
                    scanner_result = ScannerResult(
                        title=issue.get("test_name", "Security Issue"),
                        severity=severity,
                        description=issue.get("issue_text", ""),
                        scanner_name=self.get_name(),
                        file_path=file_path,
                        line_number=issue.get("line_number"),
                        remediation=self._get_remediation(issue),
                        confidence=issue.get("issue_confidence", "MEDIUM"),
                        metadata={
                            "test_id": issue.get("test_id"),
                            "cwe": issue.get("cwe", {}).get("id") if isinstance(issue.get("cwe"), dict) else None,
                            "code": issue.get("code")
                        }
                    )
                    results.append(scanner_result)
        
        except subprocess.TimeoutExpired:
            raise Exception(f"Bandit scan timed out after 300 seconds")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Bandit output: {e}")
        except Exception as e:
            raise Exception(f"Bandit scan failed: {e}")
        
        return results
    
    def _map_bandit_severity(self, severity: str, confidence: str) -> str:
        """
        Map Bandit severity and confidence to our severity levels.
        
        High severity + High confidence = HIGH
        High severity + Medium confidence = HIGH
        Medium severity + High confidence = MEDIUM
        Everything else = LOW
        
        Args:
            severity: Bandit severity (LOW/MEDIUM/HIGH)
            confidence: Bandit confidence (LOW/MEDIUM/HIGH)
            
        Returns:
            Normalized severity (HIGH/MEDIUM/LOW)
        """
        sev = severity.upper()
        conf = confidence.upper()
        
        if sev == "HIGH" and conf in ["HIGH", "MEDIUM"]:
            return "HIGH"
        elif sev == "MEDIUM" and conf == "HIGH":
            return "MEDIUM"
        elif sev == "HIGH" and conf == "LOW":
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_remediation(self, issue: dict) -> str:
        """
        Generate remediation advice from Bandit issue.
        
        Args:
            issue: Bandit issue dictionary
            
        Returns:
            Remediation string
        """
        test_id = issue.get("test_id", "")
        
        # Common remediation advice for Bandit tests
        remediation_map = {
            "B201": "Avoid using flask app.run() with debug=True in production",
            "B301": "Use pickle with caution; consider safer alternatives like JSON",
            "B303": "Avoid MD5 and SHA1 for cryptographic purposes; use SHA256 or better",
            "B304": "Avoid using insecure ciphers; use AES with proper modes",
            "B305": "Avoid using insecure cipher modes; use GCM or CBC with HMAC",
            "B306": "Use tempfile.mkstemp() instead of mktemp() to avoid race conditions",
            "B307": "Use defusedxml to parse XML and prevent XXE attacks",
            "B308": "Avoid using mark_safe(); sanitize user input properly",
            "B309": "Use HTTPSConnection instead of HTTPConnection for secure communication",
            "B310": "Avoid using urllib.urlopen(); use requests library instead",
            "B311": "Use secrets module for cryptographically secure random numbers",
            "B312": "Use subprocess with shell=False to avoid shell injection",
            "B313": "Avoid using xml.etree.ElementTree.parse(); use defusedxml instead",
            "B314": "Avoid using xml.etree.ElementTree.iterparse(); use defusedxml instead",
            "B315": "Avoid using xml.etree.ElementTree.XMLParser(); use defusedxml instead",
            "B316": "Avoid using xml.sax.parse(); use defusedxml instead",
            "B317": "Avoid using xml.sax.parseString(); use defusedxml instead",
            "B318": "Avoid using xml.sax.make_parser(); use defusedxml instead",
            "B319": "Avoid using xml.dom.minidom.parse(); use defusedxml instead",
            "B320": "Avoid using xml.dom.minidom.parseString(); use defusedxml instead",
            "B321": "Avoid using ftplib; use SFTP instead",
            "B322": "Avoid using input() in Python 2; use raw_input() instead",
            "B323": "Avoid using unverified SSL/TLS contexts; set verify=True",
            "B324": "Avoid using hashlib.md5() or hashlib.sha1() for security purposes",
            "B325": "Use tempfile.mkstemp() instead of tempfile.mktemp()",
            "B401": "Avoid using import telnetlib; use SSH instead",
            "B402": "Avoid using import ftplib; use SFTP instead",
            "B403": "Avoid using import pickle; consider safer alternatives",
            "B404": "Avoid using import subprocess; use with caution",
            "B405": "Avoid using import xml.etree; use defusedxml instead",
            "B406": "Avoid using import xml.sax; use defusedxml instead",
            "B407": "Avoid using import xml.dom.minidom; use defusedxml instead",
            "B408": "Avoid using import xml.dom.pulldom; use defusedxml instead",
            "B409": "Avoid using import xml.etree.ElementTree; use defusedxml instead",
            "B410": "Avoid using import lxml; use defusedxml instead",
            "B411": "Avoid using import xmlrpclib; use safer alternatives",
            "B412": "Avoid using import httpoxy; ensure proper HTTP header handling",
            "B413": "Avoid using import pycrypto; use cryptography library instead",
            "B501": "Avoid using SSL/TLS with weak protocols; use TLS 1.2 or higher",
            "B502": "Avoid using SSL/TLS with weak ciphers",
            "B503": "Avoid using SSL/TLS with weak key exchange",
            "B504": "Avoid using SSL/TLS without certificate validation",
            "B505": "Avoid using weak cryptographic keys",
            "B506": "Use safe YAML loader; avoid yaml.load() without Loader parameter",
            "B507": "Avoid using SSH with weak host key algorithms",
            "B601": "Avoid using paramiko with auto_add_policy",
            "B602": "Avoid using shell=True in subprocess calls",
            "B603": "Avoid using subprocess without shell=False",
            "B604": "Avoid using shell=True in subprocess calls",
            "B605": "Avoid using shell=True with user input",
            "B606": "Avoid using shell=True without input validation",
            "B607": "Avoid starting processes with partial executable paths",
            "B608": "Avoid SQL injection; use parameterized queries",
            "B609": "Avoid wildcard injection in subprocess calls",
            "B610": "Avoid SQL injection in Django; use parameterized queries",
            "B611": "Avoid SQL injection in SQLAlchemy; use parameterized queries",
            "B701": "Avoid using jinja2 autoescape=False",
            "B702": "Avoid using mako with default_filters",
            "B703": "Avoid using Django mark_safe() with user input"
        }
        
        return remediation_map.get(test_id, "Review and fix the security issue identified by Bandit")
