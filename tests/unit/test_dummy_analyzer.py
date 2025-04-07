"""
Unit tests for the dummy analyzer
"""

import os
import pytest
from eth_vuln_scanner.analyzers.dummy_analyzer import DummyAnalyzer

class TestDummyAnalyzer:
    """Test the dummy analyzer"""
    
    def test_initialization(self, mock_config):
        """Test initializing the dummy analyzer"""
        analyzer = DummyAnalyzer(mock_config)
        assert analyzer.config == mock_config
    
    def test_analyze(self, mock_config, sample_contract_dir):
        """Test analyzing a contract"""
        analyzer = DummyAnalyzer(mock_config)
        
        # Analyze the contract
        results = analyzer.analyze(sample_contract_dir)
        
        # Check the results
        assert results["success"] is True
        assert "vulnerabilities" in results
        assert len(results["vulnerabilities"]) == 3
        
        # Check the first vulnerability
        vuln = results["vulnerabilities"][0]
        assert vuln["title"] == "Reentrancy Vulnerability"
        assert vuln["severity"] == "High"
        assert "description" in vuln
        assert "recommendation" in vuln
        assert "code" in vuln
        assert "location" in vuln
