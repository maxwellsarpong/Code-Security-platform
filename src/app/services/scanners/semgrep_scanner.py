"""Semgrep scanner for multi-language security analysis."""
import json
import subprocess
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult


class SemgrepScanner(BaseScanner):
    """Scanner for multi-language security using Semgrep."""
    
    # Languages supported by Semgrep
    SUPPORTED_LANGUAGES = {
        "python": [".py"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "go": [".go"],
        "ruby": [".rb"],
        "php": [".php"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
        "csharp": [".cs"],
        "rust": [".rs"],
        "kotlin": [".kt", ".kts"],
        "scala": [".scala"],
        "swift": [".swift"],
        "yaml": [".yaml", ".yml"],
        "json": [".json"],
        "terraform": [".tf"],
        "dockerfile": ["Dockerfile"],
    }
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "semgrep"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository contains files in supported languages.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if any supported language files found
        """
        # Check for any supported file extensions
        for extensions in self.SUPPORTED_LANGUAGES.values():
            for ext in extensions:
                if ext.startswith("."):
                    if list(repo_path.rglob(f"*{ext}")):
                        return True
                else:
                    # Handle special cases like Dockerfile
                    if list(repo_path.rglob(ext)):
                        return True
        
        return False
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run Semgrep scanner on repository.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            Exception: If Semgrep fails
        """
        results = []
        
        try:
            # Run Semgrep with auto config (uses community rules)
            cmd = [
                "semgrep",
                "scan",
                "--config", "auto",  # Use Semgrep Registry rules
                "--json",  # JSON output
                "--quiet",  # Suppress progress
                str(repo_path)
            ]
            
            # Semgrep exits with code 1 if findings are present
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)
                
                # Process each finding
                for finding in data.get("results", []):
                    # Extract severity
                    severity = self._map_semgrep_severity(finding)
                    
                    # Extract file path relative to repo
                    file_path = finding.get("path", "")
                    if file_path.startswith(str(repo_path)):
                        file_path = file_path[len(str(repo_path)) + 1:]
                    
                    # Get rule information
                    check_id = finding.get("check_id", "")
                    extra = finding.get("extra", {})
                    
                    # Build description
                    message = extra.get("message", finding.get("extra", {}).get("message", "Security issue detected"))
                    
                    # Get metadata
                    metadata = extra.get("metadata", {})
                    
                    scanner_result = ScannerResult(
                        title=self._format_title(check_id, message),
                        severity=severity,
                        description=message,
                        scanner_name=self.get_name(),
                        file_path=file_path,
                        line_number=finding.get("start", {}).get("line"),
                        remediation=self._build_remediation(metadata, check_id),
                        cve_id=self._extract_cve(metadata),
                        metadata={
                            "check_id": check_id,
                            "category": metadata.get("category"),
                            "technology": metadata.get("technology"),
                            "owasp": metadata.get("owasp"),
                            "cwe": metadata.get("cwe"),
                            "confidence": metadata.get("confidence"),
                            "likelihood": metadata.get("likelihood"),
                            "impact": metadata.get("impact"),
                            "references": metadata.get("references", [])
                        }
                    )
                    results.append(scanner_result)
        
        except subprocess.TimeoutExpired:
            raise Exception(f"Semgrep scan timed out after 300 seconds")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Semgrep output: {e}")
        except FileNotFoundError:
            raise Exception("Semgrep not found. Please install it: pip install semgrep")
        except Exception as e:
            raise Exception(f"Semgrep scan failed: {e}")
        
        return results
    
    def _map_semgrep_severity(self, finding: dict) -> str:
        """
        Map Semgrep severity to our levels.
        
        Semgrep uses: ERROR, WARNING, INFO
        
        Args:
            finding: Semgrep finding dictionary
            
        Returns:
            Normalized severity (HIGH/MEDIUM/LOW)
        """
        extra = finding.get("extra", {})
        severity = extra.get("severity", "WARNING").upper()
        
        # Check metadata for additional severity info
        metadata = extra.get("metadata", {})
        impact = metadata.get("impact", "").upper()
        likelihood = metadata.get("likelihood", "").upper()
        
        # Combine severity with impact/likelihood if available
        if severity == "ERROR" or impact == "HIGH" or likelihood == "HIGH":
            return "HIGH"
        elif severity == "WARNING" or impact == "MEDIUM" or likelihood == "MEDIUM":
            return "MEDIUM"
        else:
            return "LOW"
    
    def _format_title(self, check_id: str, message: str) -> str:
        """
        Format a readable title from check ID and message.
        
        Args:
            check_id: Semgrep rule ID
            message: Finding message
            
        Returns:
            Formatted title
        """
        # Extract rule name from check_id (e.g., "python.lang.security.audit.exec-used")
        if "." in check_id:
            parts = check_id.split(".")
            rule_name = parts[-1].replace("-", " ").title()
            return rule_name
        
        # Fallback to first part of message
        if message:
            return message.split(".")[0][:100]
        
        return "Security Issue"
    
    def _build_remediation(self, metadata: dict, check_id: str) -> str:
        """
        Build remediation advice from Semgrep metadata.
        
        Args:
            metadata: Semgrep metadata dictionary
            check_id: Rule ID
            
        Returns:
            Remediation string
        """
        # Check for fix message in metadata
        fix_message = metadata.get("fix", metadata.get("fix_regex"))
        if fix_message:
            return fix_message
        
        # Check for references
        references = metadata.get("references", [])
        if references:
            ref_links = ", ".join(references[:2])  # Limit to 2 references
            return f"Review and fix the security issue. See: {ref_links}"
        
        # Generic remediation based on category
        category = metadata.get("category", "").lower()
        if "injection" in category:
            return "Use parameterized queries or input validation to prevent injection attacks"
        elif "crypto" in category:
            return "Use secure cryptographic algorithms and proper key management"
        elif "auth" in category:
            return "Implement proper authentication and authorization controls"
        elif "xss" in category:
            return "Sanitize user input and use context-aware output encoding"
        
        return "Review and fix the security issue identified by Semgrep"
    
    def _extract_cve(self, metadata: dict) -> str:
        """
        Extract CVE ID from metadata if present.
        
        Args:
            metadata: Semgrep metadata dictionary
            
        Returns:
            CVE ID or None
        """
        # Check for CVE in references
        references = metadata.get("references", [])
        for ref in references:
            if "CVE-" in ref:
                # Extract CVE ID
                import re
                match = re.search(r'CVE-\d{4}-\d+', ref)
                if match:
                    return match.group(0)
        
        # Check for CWE (Common Weakness Enumeration)
        cwe = metadata.get("cwe")
        if cwe:
            if isinstance(cwe, list) and cwe:
                return f"CWE-{cwe[0]}"
            elif isinstance(cwe, str):
                return f"CWE-{cwe}"
        
        return None
