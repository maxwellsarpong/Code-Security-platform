import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json
from app.services.scanners.npm_audit_scanner import NpmAuditScanner

def test_npm_audit_scanner_is_applicable():
    """Test NpmAuditScanner detects relevant dependency files."""
    scanner = NpmAuditScanner()
    
    with patch("pathlib.Path.exists") as mock_exists:
        # Match package.json
        mock_exists.side_effect = lambda: True
        assert scanner.is_applicable(Path("/tmp/foo")) is True

def test_npm_audit_scanner_v2_parsing():
    """Test NpmAuditScanner correctly parses npm audit v2 JSON."""
    scanner = NpmAuditScanner()
    
    mock_json_output = {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "source": 1094254,
                        "name": "lodash",
                        "dependency": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
                        "severity": "high",
                        "cves": [
                            "CVE-2020-8203"
                        ],
                        "cvss": {
                            "score": 7.4,
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"
                        },
                        "range": "<4.17.16"
                    }
                ],
                "effects": [],
                "range": "<4.17.16",
                "nodes": [
                    "node_modules/lodash"
                ],
                "fixAvailable": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "isSemVerMajor": False
                }
            }
        },
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": 1,
                "critical": 0,
                "total": 1
            },
            "dependencies": {
                "prod": 1,
                "dev": 0,
                "optional": 0,
                "peer": 0,
                "peerOptional": 0,
                "total": 1
            }
        }
    }
    
    with patch("subprocess.run") as mock_run, patch("pathlib.Path.exists") as mock_exists:
        # mock exists for package.json = True
        mock_exists.return_value = True
        
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(mock_json_output)
        mock_run.return_value = mock_result
        
        results = scanner.scan(Path("/app"))
        
        assert len(results) == 1
        finding = results[0]
        assert finding.scanner_name == "npm-audit"
        assert "lodash" in finding.title
        assert "Prototype Pollution in lodash" in finding.title
        assert finding.cve_id == "CVE-2020-8203"
        assert finding.severity == "HIGH"

def test_npm_audit_scanner_v1_parsing():
    """Test NpmAuditScanner correctly parses npm audit v1 JSON fallback."""
    scanner = NpmAuditScanner()
    
    mock_json_output = {
        "advisories": {
            "1523": {
                "findings": [
                    {
                        "version": "4.17.15",
                        "paths": [
                            "lodash"
                        ]
                    }
                ],
                "id": 1523,
                "created": "2020-07-06T15:06:58.336Z",
                "updated": "2021-08-30T17:49:15.539Z",
                "deleted": None,
                "title": "Prototype Pollution",
                "found_by": {
                    "link": "",
                    "name": "Snyk Security Research Team"
                },
                "reported_by": {
                    "link": "",
                    "name": "Snyk Security Research Team"
                },
                "module_name": "lodash",
                "cves": [
                    "CVE-2020-8203"
                ],
                "vulnerable_versions": "<4.17.19",
                "patched_versions": ">=4.17.19",
                "overview": "lodash before 4.17.19...",
                "recommendation": "Upgrade to version 4.17.19 or later.",
                "references": "- https://hackerone.com/reports/712065\n- https://github.com/lodash/lodash/wiki/Changelog",
                "access": "public",
                "severity": "high",
                "cwe": "CWE-400",
                "metadata": {
                    "module_type": "",
                    "exploitability": 5,
                    "affected_components": ""
                },
                "url": "https://npmjs.com/advisories/1523"
            }
        }
    }
    
    with patch("subprocess.run") as mock_run, patch("pathlib.Path.exists") as mock_exists:
        # mock exists for package.json = True
        mock_exists.return_value = True
        
        mock_result = MagicMock()
        mock_result.stdout = json.dumps(mock_json_output)
        mock_run.return_value = mock_result
        
        results = scanner.scan(Path("/app"))
        
        assert len(results) == 1
        finding = results[0]
        assert finding.scanner_name == "npm-audit"
        assert "lodash" in finding.title
        assert "Prototype Pollution" in finding.title
        assert finding.cve_id == "CVE-2020-8203"
        assert finding.severity == "HIGH"
