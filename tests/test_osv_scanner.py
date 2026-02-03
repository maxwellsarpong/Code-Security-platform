import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from app.services.scanners.osv_scanner import OSVScanner

def test_osv_scanner_is_applicable():
    """Test OSVScanner detects relevant dependency files."""
    scanner = OSVScanner()
    
    with patch.object(Path, "rglob") as mock_rglob:
        # 1. Matches package-lock.json
        mock_rglob.side_effect = lambda p: iter([Path("package-lock.json")]) if p == "package-lock.json" else iter([])
        assert scanner.is_applicable(Path("/tmp/foo")) is True
        
        # 2. Matches go.mod
        mock_rglob.side_effect = lambda p: iter([Path("go.mod")]) if p == "go.mod" else iter([])
        assert scanner.is_applicable(Path("/tmp/foo")) is True
        
        # 3. No match
        mock_rglob.side_effect = lambda p: iter([])
        assert scanner.is_applicable(Path("/tmp/foo")) is False

def test_osv_scanner_scan_parses_json():
    """Test OSVScanner correctly parses the JSON output from osv-scanner."""
    scanner = OSVScanner()
    
    mock_json_output = {
        "results": [
            {
                "source": {"path": "/app/package-lock.json", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "lodash",
                            "version": "4.17.20",
                            "ecosystem": "npm"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-35jh-8hc6-5mc8",
                                "summary": "Prototype Pollution in lodash",
                                "aliases": ["CVE-2020-8203", "CVE-2021-23337"]
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(mock_json_output)
        mock_run.return_value = mock_result
        
        results = scanner.scan(Path("/app"))
        
        assert len(results) == 1
        finding = results[0]
        assert finding.scanner_name == "osv-scanner"
        assert "lodash" in finding.title
        assert finding.cve_id == "CVE-2020-8203"
        assert finding.severity == "HIGH"

import json # needed for the test
