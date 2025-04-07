"""
Integration with the Mythril symbolic execution analyzer
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

class MythrilAnalyzer:
    """Analyzer that uses Mythril to find vulnerabilities"""
    
    def __init__(self, config):
        """
        Initialize the Mythril analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get("timeout", 300)
        
        # Check if Mythril is installed
        try:
            result = subprocess.run(
                ["myth", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError("Mythril is not installed or not working properly")
        except (subprocess.SubprocessError, FileNotFoundError):
            raise RuntimeError("Mythril is not installed or not in PATH")
    
    def analyze(self, contract_dir):
        """
        Analyze a contract using Mythril
        
        Args:
            contract_dir: Directory containing the contract source code
            
        Returns:
            dict: Analysis results
        """
        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
            output_file = temp_file.name
        
        try:
            # Find Solidity files in the directory
            solidity_files = []
            for root, _, files in os.walk(contract_dir):
                for file in files:
                    if file.endswith(".sol"):
                        solidity_files.append(os.path.join(root, file))
            
            if not solidity_files:
                return {
                    "success": False,
                    "error": "No Solidity files found in the contract directory"
                }
            
            # Run Mythril on each Solidity file
            all_vulnerabilities = []
            
            for sol_file in solidity_files:
                # Run Mythril with JSON output
                cmd = [
                    "myth", "analyze",
                    sol_file,
                    "--solv", "0.8.0",  # Default to Solidity 0.8.0 (can be improved)
                    "-o", "json",
                    "-t", str(self.timeout)
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                
                # Parse the JSON output
                try:
                    mythril_output = json.loads(result.stdout)
                    file_vulnerabilities = self._parse_mythril_output(mythril_output, os.path.basename(sol_file))
                    all_vulnerabilities.extend(file_vulnerabilities)
                except json.JSONDecodeError:
                    # If Mythril doesn't return valid JSON, continue with other files
                    continue
            
            return {
                "success": True,
                "vulnerabilities": all_vulnerabilities
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Mythril analysis timed out after {self.timeout} seconds"
            }
        except subprocess.SubprocessError as e:
            return {
                "success": False,
                "error": f"Mythril analysis failed: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error during Mythril analysis: {str(e)}"
            }
        finally:
            # Clean up the temporary file
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_mythril_output(self, mythril_output, filename):
        """
        Parse Mythril output into a standardized format
        
        Args:
            mythril_output: Mythril JSON output
            filename: Name of the analyzed file
            
        Returns:
            list: Standardized vulnerability list
        """
        vulnerabilities = []
        
        if not isinstance(mythril_output, list):
            return vulnerabilities
        
        for issue in mythril_output:
            # Map Mythril severity to our severity levels
            severity_map = {
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Informational": "Low"
            }
            
            severity = severity_map.get(issue.get("severity", ""), "Unknown")
            
            # Extract code snippet if available
            code = ""
            if "code" in issue:
                code = issue["code"]
            
            # Create vulnerability entry
            vulnerability = {
                "title": issue.get("title", "Unknown Vulnerability"),
                "severity": severity,
                "description": issue.get("description", {}).get("head", ""),
                "recommendation": issue.get("description", {}).get("tail", ""),
            }
            
            if code:
                vulnerability["code"] = code
            
            if "lineno" in issue:
                vulnerability["location"] = f"{filename}:{issue['lineno']}"
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
