"""Base scanner interface for all security scanners."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path


class ScannerResult:
    """Represents a single finding from a scanner."""
    
    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        scanner_name: str,
        file_path: str = None,
        line_number: int = None,
        remediation: str = None,
        cve_id: str = None,
        confidence: str = None,
        metadata: Dict[str, Any] = None
    ):
        self.title = title
        self.severity = severity.upper()  # Normalize to HIGH/MEDIUM/LOW
        self.description = description
        self.scanner_name = scanner_name
        self.file_path = file_path
        self.line_number = line_number
        self.remediation = remediation
        self.cve_id = cve_id
        self.confidence = confidence
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "scanner_name": self.scanner_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the scanner name."""
        pass
    
    @abstractmethod
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if this scanner is applicable to the given repository.
        
        Args:
            repo_path: Path to the cloned repository
            
        Returns:
            True if scanner should run on this repository
        """
        pass
    
    @abstractmethod
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Execute the scanner on the repository.
        
        Args:
            repo_path: Path to the cloned repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            Exception: If scanner execution fails
        """
        pass
    
    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize severity levels to HIGH/MEDIUM/LOW.
        
        Args:
            severity: Raw severity string from scanner
            
        Returns:
            Normalized severity (HIGH/MEDIUM/LOW)
        """
        severity_upper = severity.upper()
        
        # Map common severity levels
        if severity_upper in ["HIGH", "CRITICAL", "ERROR"]:
            return "HIGH"
        elif severity_upper in ["MEDIUM", "WARNING", "MODERATE"]:
            return "MEDIUM"
        elif severity_upper in ["LOW", "INFO", "NOTE", "MINOR"]:
            return "LOW"
        else:
            return "MEDIUM"  # Default to MEDIUM if unknown
