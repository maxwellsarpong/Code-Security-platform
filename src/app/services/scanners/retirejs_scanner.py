"""Retire.js scanner for bundled JavaScript vulnerability detection."""
import json
import subprocess
import logging
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult

logger = logging.getLogger(__name__)


class RetirejsScanner(BaseScanner):
    """Scanner for bundled JavaScript framework vulnerabilities using Retire.js."""
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "retire.js"
    
    def is_applicable(self, repo_path: Path) -> bool:
        """
        Check if repository has bundled `.js` files.
        Retire.js is specifically good at finding bundled, outdated JS like jQuery.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            True if any non-node_modules JS files exist.
        """
        # Look for any .js files (excluding node_modules optimally via skip mechanism if iterating heavily, 
        # but for quick applicable check we just need one non-node_module .js file)
        for js_file in repo_path.rglob("*.js"):
            if "node_modules" not in str(js_file):
                return True
        return False
    
    def scan(self, repo_path: Path) -> List[ScannerResult]:
        """
        Run Retire.js scanner on the repository.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of ScannerResult objects
            
        Raises:
            Exception: If retire.js execution fails
        """
        results = []
        
        try:
            # We use `npx retire` to run it dynamically without needing global installation.
            # Using --outputformat json ensures we can parse the findings.
            cmd = [
                "npx", 
                "--yes", # auto-confirm installation of the npx package dynamically if not present
                "retire", 
                "--jspath", str(repo_path), # Only focus on JS files directly
                "--outputformat", "json"
            ]
            
            # Retire.js exits with code 13 if vulnerabilities are found
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(repo_path)
            )
            
            # Parsing Retire.js stdout. Depending on the version it might output to stdout or stderr.
            output = result.stdout if result.stdout.strip().startswith("[") or result.stdout.strip().startswith("{") else result.stderr
            
            # Sometimes npx outputs warnings "Need to install the following packages...".
            # We must isolate the JSON part.
            try:
                # Find the first valid JSON array
                start_idx = output.index('[{"') if '[{"' in output else output.index('data":[{') if 'data":[{' in output else 0
                if 'data":[{' in output:
                    start_idx = output.index('{') # the root object 
                json_str = output[start_idx:]
                
                # In case there's trailing non-json data
                end_idx = json_str.rindex(']') + 1 if ']' in json_str else len(json_str)
                if json_str.strip().endswith('}'):
                    end_idx = json_str.rindex('}') + 1 
                json_str = json_str[:end_idx]
                
                data = json.loads(json_str)
            except (ValueError, json.JSONDecodeError):
                # We couldn't dynamically find a json string. If no vulnerabilities are found, it often prints nothing or text block.
                # If there are definitely no json brackets, return empty.
                if not ("[" in output and "]" in output) and not ("{" in output and "}" in output):
                     return results
                
                # As a last fallback just try to parse the entire raw block
                data = json.loads(output)
            
            # Format depends on retire version: sometimes it's direct array, sometimes {"version":..., "data": [...]}
            findings_array = data if isinstance(data, list) else data.get("data", [])
            
            logger.info(f"Retire.js found issues in {len(findings_array)} files.")
            
            for file_entry in findings_array:
                file_path = file_entry.get("file", "")
                
                # Make path relative to repo root
                if file_path.startswith(str(repo_path)):
                    file_path = file_path[len(str(repo_path)) + 1:]
                
                # Exclude explicitly node_modules, environments, tests just in case.
                if "node_modules/" in file_path or "env/" in file_path or ".env/" in file_path:
                    continue
                    
                for result_entry in file_entry.get("results", []):
                    component = result_entry.get("component", "unknown library")
                    version = result_entry.get("version", "unknown version")
                    
                    for vuln in result_entry.get("vulnerabilities", []):
                        severity = vuln.get("severity", "medium").upper()
                        # RetireJS sometimes outputs severities like "medium", "high", "critical"
                        if severity == "CRITICAL":
                            severity = "HIGH"
                            
                        # Extract CVEs
                        cve_list = vuln.get("identifiers", {}).get("CVE", [])
                        cve_id = cve_list[0] if cve_list else None
                        
                        summary = vuln.get("identifiers", {}).get("summary", f"Vulnerable version of {component} detected.")
                        # Truncate summary for title if it's too long, but keep it descriptive
                        short_summary = summary if len(summary) < 80 else summary[:77] + "..."
                        
                        info_urls = vuln.get("info", [])
                        
                        desc_text = f"{component} {version} has a known vulnerability: {summary}."
                        if info_urls:
                             desc_text += f"\nMore info: {info_urls[0]}"
                             
                        scanner_result = ScannerResult(
                            title=f"{component} vulnerability: {short_summary}",
                            severity=severity,
                            description=desc_text,
                            scanner_name=self.get_name(),
                            file_path=file_path,
                            remediation=f"Update the bundled {component} library ({file_path}) to a secure version.",
                            cve_id=cve_id,
                            confidence="HIGH",
                            metadata={
                                "component": component,
                                "version": version,
                                "identifiers": vuln.get("identifiers", {}),
                                "info": info_urls
                            }
                        )
                        results.append(scanner_result)
                        
        except subprocess.TimeoutExpired:
            raise Exception(f"Retire.js scan timed out after 300 seconds")
        except json.JSONDecodeError as e:
            # If nothing was found, output format might just be messy non-json. We consider it 0 findings.
             pass 
        except FileNotFoundError:
            raise Exception("npx not found. Please install Node.js and npm to use Retire.js scanner.")
        except Exception as e:
            raise Exception(f"Retire.js scan failed: {e}")
            
        return results
