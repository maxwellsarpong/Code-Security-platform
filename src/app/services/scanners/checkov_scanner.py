"""Checkov scanner for Infrastructure as Code security scanning."""
import json
import subprocess
import logging
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult

logger = logging.getLogger(__name__)


class CheckovScanner(BaseScanner):
    """Scanner for IaC security using Checkov."""
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "checkov"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository contains IaC files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if Terraform, Dockerfile, K8s, or CloudFormation files found
        """
        # Check for various IaC file types
        iac_patterns = [
            "*.tf",  # Terraform
            "Dockerfile*",  # Docker
            "*.yaml",  # Kubernetes/CloudFormation
            "*.yml",  # Kubernetes/CloudFormation
            "*.json"  # CloudFormation/K8s
        ]
        
        for pattern in iac_patterns:
            if next(repo_path.rglob(pattern), None):
                return True
        
        return False
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run Checkov scanner on IaC files.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            subprocess.CalledProcessError: If Checkov fails
        """
        results = []
        
        try:
            # Run Checkov with JSON output
            cmd = [
                "checkov",
                "-d", str(repo_path),  # Directory to scan
                "-o", "json",  # JSON output
                "--quiet",  # Suppress progress
                "--compact",  # Compact output
                "--skip-path", "env",
                "--skip-path", ".env"
            ]
            
            # Checkov exits with code 1 if issues found
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            # Parse JSON output
            if result.stdout:
                data = json.loads(result.stdout)
                
                # Checkov returns a list if multiple frameworks are scanned, or a single dict
                all_failed_checks = []
                if isinstance(data, list):
                    for item in data:
                        checks = item.get("results", {}).get("failed_checks", [])
                        all_failed_checks.extend(checks)
                elif isinstance(data, dict):
                    all_failed_checks = data.get("results", {}).get("failed_checks", [])
                
                logger.info(f"Checkov found {len(all_failed_checks)} issues.")
                
                for check_type in all_failed_checks:
                    # Extract file path relative to repo
                    file_path = check_type.get("file_path", "")
                    if file_path.startswith(str(repo_path)):
                        file_path = file_path[len(str(repo_path)) + 1:]
                    elif file_path.startswith("/"):
                        # Try to make it relative
                        try:
                            file_path = str(Path(file_path).relative_to(repo_path))
                        except ValueError:
                            pass  # Keep absolute path if can't make relative
                    
                    # Map Checkov severity
                    severity = self._map_checkov_severity(check_type.get("severity"))
                    
                    # Build description
                    description = check_type.get("description", "")
                    guideline = check_type.get("guideline")
                    if guideline:
                        description = f"{description}\n\nGuideline: {guideline}"
                    
                    scanner_result = ScannerResult(
                        title=check_type.get("check_name", "IaC Security Issue"),
                        severity=severity,
                        description=description,
                        scanner_name=self.get_name(),
                        file_path=file_path,
                        line_number=self._extract_line_number(check_type),
                        remediation=self._build_remediation(check_type),
                        metadata={
                            "check_id": check_type.get("check_id"),
                            "check_class": check_type.get("check_class"),
                            "resource": check_type.get("resource"),
                            "framework": check_type.get("check_type"),
                            "guideline_url": guideline
                        }
                    )
                    results.append(scanner_result)
        
        except subprocess.TimeoutExpired:
            raise Exception(f"Checkov scan timed out after 300 seconds")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse Checkov output: {e}")
        except FileNotFoundError:
            raise Exception("Checkov not found. Please install it: pip install checkov")
        except Exception as e:
            raise Exception(f"Checkov scan failed: {e}")
        
        return results
    
    def _map_checkov_severity(self, severity: str) -> str:
        """
        Map Checkov severity to our levels.
        
        Args:
            severity: Checkov severity (CRITICAL/HIGH/MEDIUM/LOW)
            
        Returns:
            Normalized severity (HIGH/MEDIUM/LOW)
        """
        if not severity:
            return "MEDIUM"
        
        severity_upper = severity.upper()
        
        if severity_upper in ["CRITICAL", "HIGH"]:
            return "HIGH"
        elif severity_upper == "MEDIUM":
            return "MEDIUM"
        elif severity_upper == "LOW":
            return "LOW"
        else:
            return "MEDIUM"
    
    def _extract_line_number(self, check: dict) -> int:
        """
        Extract line number from Checkov check.
        
        Args:
            check: Checkov check dictionary
            
        Returns:
            Line number or None
        """
        # Checkov provides line range
        file_line_range = check.get("file_line_range", [])
        if file_line_range and len(file_line_range) > 0:
            return file_line_range[0]  # Return start line
        
        return None
    
    def _build_remediation(self, check: dict) -> str:
        """
        Build remediation advice from Checkov check.
        
        Args:
            check: Checkov check dictionary
            
        Returns:
            Remediation string
        """
        # Use guideline if available
        guideline = check.get("guideline")
        if guideline:
            return f"Follow the guideline: {guideline}"
        
        # Build generic remediation based on check type
        check_id = check.get("check_id", "")
        resource = check.get("resource", "")
        
        remediation_templates = {
            "CKV_AWS": "Review AWS resource configuration for security best practices",
            "CKV_AZURE": "Review Azure resource configuration for security best practices",
            "CKV_GCP": "Review GCP resource configuration for security best practices",
            "CKV_K8S": "Review Kubernetes manifest for security best practices",
            "CKV_DOCKER": "Review Dockerfile for security best practices",
            "CKV2": "Review infrastructure configuration for security compliance"
        }
        
        for prefix, template in remediation_templates.items():
            if check_id.startswith(prefix):
                if resource:
                    return f"{template} for resource: {resource}"
                return template
        
        return "Review and fix the security issue identified by Checkov"
