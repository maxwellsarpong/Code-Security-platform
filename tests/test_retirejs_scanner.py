import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json
from app.services.scanners.retirejs_scanner import RetirejsScanner

def test_retirejs_scanner_is_applicable():
    """Test RetirejsScanner detects relevant js files."""
    scanner = RetirejsScanner()
    
    with patch("pathlib.Path.rglob") as mock_rglob:
        # Match random js file
        mock_rglob.return_value = iter([Path("/tmp/foo/app.js")])
        assert scanner.is_applicable(Path("/tmp/foo")) is True

        # Ignore node_modules
        mock_rglob.return_value = iter([Path("/tmp/foo/node_modules/app.js")])
        assert scanner.is_applicable(Path("/tmp/foo")) is False

        # No match
        mock_rglob.return_value = iter([])
        assert scanner.is_applicable(Path("/tmp/foo")) is False

def test_retirejs_scanner_parsing():
    """Test RetirejsScanner correctly parses Retire.js JSON format."""
    scanner = RetirejsScanner()
    
    mock_json_output = [
        {
            "file": "/app/static/js/jquery-3.4.1.min.js",
            "results": [
                {
                    "version": "3.4.1",
                    "component": "jquery",
                    "vulnerabilities": [
                        {
                            "info": [
                                "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
                                "https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5vhx"
                            ],
                            "severity": "medium",
                            "identifiers": {
                                "CVE": [
                                    "CVE-2020-11022"
                                ],
                                "github": [
                                    "GHSA-gxr4-xjj5-5vhx"
                                ],
                                "summary": "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS"
                            }
                        }
                    ]
                }
            ]
        }
    ]
    
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(mock_json_output)
        mock_run.return_value = mock_result
        
        results = scanner.scan(Path("/app"))
        
        assert len(results) == 1
        finding = results[0]
        assert finding.scanner_name == "retire.js"
        assert "jquery" in finding.title
        assert "Regex in its jQuery.htmlPrefilter" in finding.title
        assert finding.cve_id == "CVE-2020-11022"
        assert finding.severity == "MEDIUM"
        assert "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS" in finding.description
        assert "static/js/jquery-3.4.1.min.js" in finding.file_path
