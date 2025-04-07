"""
Dummy analyzer for demonstration purposes
"""

class DummyAnalyzer:
    """A simple analyzer that returns predefined results for demonstration"""
    
    def __init__(self, config):
        """
        Initialize the dummy analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
    
    def analyze(self, contract_dir):
        """
        Return predefined analysis results
        
        Args:
            contract_dir: Directory containing the contract source code
            
        Returns:
            dict: Analysis results
        """
        return {
            "success": True,
            "vulnerabilities": [
                {
                    "title": "Reentrancy Vulnerability",
                    "severity": "High",
                    "description": "The contract may be vulnerable to reentrancy attacks. This is a demonstration result.",
                    "recommendation": "Use a reentrancy guard or follow the checks-effects-interactions pattern.",
                    "code": "function withdraw(uint amount) public {\n    require(balances[msg.sender] >= amount);\n    (bool success, ) = msg.sender.call{value: amount}(\"\");\n    require(success);\n    balances[msg.sender] -= amount;\n}",
                    "location": "Contract.sol:42"
                },
                {
                    "title": "Unchecked External Call",
                    "severity": "Medium",
                    "description": "The contract does not check the return value of an external call. This is a demonstration result.",
                    "recommendation": "Always check the return value of external calls.",
                    "code": "function sendFunds(address recipient, uint amount) public {\n    recipient.call{value: amount}(\"\");\n}",
                    "location": "Contract.sol:78"
                },
                {
                    "title": "Integer Overflow",
                    "severity": "Low",
                    "description": "The contract may be vulnerable to integer overflow. This is a demonstration result.",
                    "recommendation": "Use SafeMath or Solidity 0.8.0+ which has built-in overflow checking.",
                    "code": "function add(uint a, uint b) public pure returns (uint) {\n    return a + b;\n}",
                    "location": "Contract.sol:103"
                }
            ]
        }
