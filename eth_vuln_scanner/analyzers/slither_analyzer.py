"""
Integration with the Slither static analyzer
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

class SlitherAnalyzer:
    """Analyzer that uses Slither to find vulnerabilities"""
    
    def __init__(self, config):
        """
        Initialize the Slither analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get("timeout", 300)
        
        # Check if Slither is installed
        try:
            result = subprocess.run(
                ["slither", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError("Slither is not installed or not working properly")
        except (subprocess.SubprocessError, FileNotFoundError):
            raise RuntimeError("Slither is not installed or not in PATH")
    
    def analyze(self, contract_dir):
        """
        Analyze a contract using Slither
        
        Args:
            contract_dir: Directory containing the contract source code
            
        Returns:
            dict: Analysis results
        """
        # Create a temporary file for the JSON output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
            output_file = temp_file.name
        
        try:
            # Run Slither with JSON output
            cmd = [
                "slither",
                contract_dir,
                "--json", output_file,
                "--filter-paths", "(node_modules|openzeppelin)"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Parse the JSON output
            with open(output_file, "r") as f:
                slither_output = json.load(f)
            
            # Convert Slither output to our format
            return self._parse_slither_output(slither_output)
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Slither analysis timed out after {self.timeout} seconds"
            }
        except subprocess.SubprocessError as e:
            return {
                "success": False,
                "error": f"Slither analysis failed: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error during Slither analysis: {str(e)}"
            }
        finally:
            # Clean up the temporary file
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_slither_output(self, slither_output):
        """
        Parse Slither output into a standardized format
        
        Args:
            slither_output: Slither JSON output
            
        Returns:
            dict: Standardized analysis results
        """
        results = {
            "success": True,
            "vulnerabilities": []
        }
        
        # Extract detectors results
        if "results" in slither_output and "detectors" in slither_output["results"]:
            for detector in slither_output["results"]["detectors"]:
                # Map Slither severity to our severity levels
                severity_map = {
                    "High": "High",
                    "Medium": "Medium",
                    "Low": "Low",
                    "Informational": "Low",
                    "Optimization": "Low"
                }
                
                severity = severity_map.get(detector.get("impact", ""), "Unknown")
                
                # Extract code snippet if available
                code = ""
                if "elements" in detector and detector["elements"]:
                    for element in detector["elements"]:
                        if "source_mapping" in element and "lines" in element["source_mapping"]:
                            lines = element["source_mapping"]["lines"]
                            if lines:
                                code += f"Lines {', '.join(map(str, lines))}\n"
                
                # Create vulnerability entry
                vulnerability = {
                    "title": detector.get("check", "Unknown Vulnerability"),
                    "severity": severity,
                    "description": detector.get("description", ""),
                    "recommendation": detector.get("recommendation", ""),
                }
                
                if code:
                    vulnerability["code"] = code
                
                if "elements" in detector and detector["elements"]:
                    locations = []
                    for element in detector["elements"]:
                        if "source_mapping" in element and "filename_absolute" in element["source_mapping"]:
                            filename = os.path.basename(element["source_mapping"]["filename_absolute"])
                            lines = element["source_mapping"].get("lines", [])
                            if lines:
                                locations.append(f"{filename}:{lines[0]}")
                    
                    if locations:
                        vulnerability["location"] = ", ".join(locations)
                
                results["vulnerabilities"].append(vulnerability)
        
        return results
