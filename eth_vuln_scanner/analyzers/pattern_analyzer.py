"""
Pattern-based analyzer for detecting common vulnerabilities
"""

import os
import re
from pathlib import Path

class PatternAnalyzer:
    """Analyzer that uses regex patterns to find potential vulnerabilities"""
    
    def __init__(self, config):
        """
        Initialize the pattern analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Define vulnerability patterns
        self.patterns = [
            {
                "name": "Reentrancy",
                "severity": "High",
                "pattern": r"(\.\s*call\s*{[^}]*value\s*:|\.\s*call\s*\.value\s*\()[^;]*\)(?!\s*returns\s*\([^)]*\)\s*{)(?![^;]*revert)(?![^;]*require\s*\()(?=[^;]*;)",
                "description": "Potential reentrancy vulnerability detected. External calls are made before state changes.",
                "recommendation": "Follow the checks-effects-interactions pattern or use a reentrancy guard."
            },
            {
                "name": "Unchecked External Call",
                "severity": "Medium",
                "pattern": r"(\.\s*call\s*{|\.\s*call\s*\(|\.\s*transfer\s*\(|\.\s*send\s*\()[^;]*\)(?!\s*returns)(?![^;]*revert)(?![^;]*require)(?![^;]*assert)(?=[^;]*;)",
                "description": "Unchecked external call detected. The return value of the call is not checked.",
                "recommendation": "Always check the return value of external calls and handle potential failures."
            },
            {
                "name": "Use of tx.origin",
                "severity": "Medium",
                "pattern": r"tx\s*\.\s*origin",
                "description": "Use of tx.origin detected. This can be manipulated by attackers in phishing attacks.",
                "recommendation": "Use msg.sender instead of tx.origin for authentication."
            },
            {
                "name": "Timestamp Dependence",
                "severity": "Low",
                "pattern": r"block\s*\.\s*timestamp",
                "description": "Timestamp dependence detected. Miners can manipulate block timestamps.",
                "recommendation": "Avoid using block.timestamp for critical logic or random number generation."
            },
            {
                "name": "Inline Assembly",
                "severity": "Low",
                "pattern": r"assembly\s*{",
                "description": "Use of inline assembly detected. This bypasses Solidity safety checks.",
                "recommendation": "Avoid using inline assembly unless absolutely necessary."
            },
            {
                "name": "Floating Pragma",
                "severity": "Low",
                "pattern": r"pragma\s+solidity\s+[\^~>]",
                "description": "Floating pragma detected. This can lead to inconsistent behavior across different compiler versions.",
                "recommendation": "Use a fixed pragma version to ensure consistent compilation."
            },
            {
                "name": "Unprotected Self-Destruct",
                "severity": "High",
                "pattern": r"(selfdestruct|suicide)\s*\([^;]*\)(?![^;]*onlyOwner)(?![^;]*require\s*\(\s*msg\.sender\s*==)",
                "description": "Unprotected self-destruct detected. Anyone might be able to destroy the contract.",
                "recommendation": "Add access control to self-destruct operations."
            },
            {
                "name": "Delegatecall to Untrusted Contract",
                "severity": "High",
                "pattern": r"\.delegatecall\s*\([^;]*\)(?![^;]*require)(?![^;]*assert)(?![^;]*revert)",
                "description": "Delegatecall to potentially untrusted contract detected. This can lead to malicious code execution.",
                "recommendation": "Only use delegatecall with trusted contracts and add proper validation."
            }
        ]
    
    def analyze(self, contract_dir):
        """
        Analyze a contract using pattern matching
        
        Args:
            contract_dir: Directory containing the contract source code
            
        Returns:
            dict: Analysis results
        """
        vulnerabilities = []
        
        # Find all Solidity files in the directory
        solidity_files = []
        for root, _, files in os.walk(contract_dir):
            for file in files:
                if file.endswith(".sol"):
                    solidity_files.append(os.path.join(root, file))
        
        # Analyze each file
        for file_path in solidity_files:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                
                # Get the relative path for reporting
                rel_path = os.path.relpath(file_path, contract_dir)
                
                # Check each pattern
                for pattern_info in self.patterns:
                    matches = re.finditer(pattern_info["pattern"], content)
                    
                    for match in matches:
                        # Get the line number
                        line_number = content[:match.start()].count("\n") + 1
                        
                        # Get the line content
                        lines = content.split("\n")
                        line_content = lines[line_number - 1] if line_number <= len(lines) else ""
                        
                        # Get some context (a few lines before and after)
                        context_start = max(0, line_number - 3)
                        context_end = min(len(lines), line_number + 2)
                        context = "\n".join(lines[context_start:context_end])
                        
                        # Create vulnerability entry
                        vulnerability = {
                            "title": pattern_info["name"],
                            "severity": pattern_info["severity"],
                            "description": pattern_info["description"],
                            "recommendation": pattern_info["recommendation"],
                            "location": f"{rel_path}:{line_number}",
                            "code": context
                        }
                        
                        vulnerabilities.append(vulnerability)
            
            except Exception as e:
                # Log the error but continue with other files
                print(f"Error analyzing {file_path}: {str(e)}")
        
        return {
            "success": True,
            "vulnerabilities": vulnerabilities
        }
