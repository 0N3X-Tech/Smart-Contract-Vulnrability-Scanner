"""
Integration tests for the scanner
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from eth_vuln_scanner.scanner import Scanner
from eth_vuln_scanner.analyzers.dummy_analyzer import DummyAnalyzer

class TestScanner:
    """Test the scanner"""
    
    @pytest.fixture
    def mock_ethereum_client(self, sample_contract_source):
        """Return a mock Ethereum client"""
        mock_client = MagicMock()
        
        # Mock the save_contract_source method
        def mock_save_contract_source(address, output_dir=None):
            if output_dir is None:
                output_dir = tempfile.mkdtemp()
            
            # Create a contract file
            contract_file = os.path.join(output_dir, "TestContract.sol")
            with open(contract_file, "w") as f:
                f.write(sample_contract_source)
            
            return output_dir
        
        mock_client.save_contract_source.side_effect = mock_save_contract_source
        
        return mock_client
    
    def test_scanner_initialization(self, mock_config):
        """Test initializing the scanner"""
        with patch('eth_vuln_scanner.scanner.EthereumClient'):
            with patch('eth_vuln_scanner.scanner.SlitherAnalyzer', side_effect=RuntimeError):
                with patch('eth_vuln_scanner.scanner.MythrilAnalyzer', side_effect=RuntimeError):
                    scanner = Scanner(mock_config)
                    assert scanner.config == mock_config
                    assert "dummy" in scanner.analyzers
                    assert isinstance(scanner.analyzers["dummy"], DummyAnalyzer)
    
    def test_scanner_scan(self, mock_config, mock_ethereum_client):
        """Test scanning a contract"""
        with patch('eth_vuln_scanner.scanner.EthereumClient', return_value=mock_ethereum_client):
            with patch('eth_vuln_scanner.scanner.SlitherAnalyzer', side_effect=RuntimeError):
                with patch('eth_vuln_scanner.scanner.MythrilAnalyzer', side_effect=RuntimeError):
                    scanner = Scanner(mock_config)
                    
                    # Scan a contract
                    results = scanner.scan("0x1234567890123456789012345678901234567890")
                    
                    # Check that the contract address was stored in the config
                    assert scanner.config["contract_address"] == "0x1234567890123456789012345678901234567890"
                    
                    # Check that the Ethereum client was called
                    mock_ethereum_client.save_contract_source.assert_called_once_with("0x1234567890123456789012345678901234567890")
                    
                    # Check the results
                    assert "dummy" in results
                    assert results["dummy"]["success"] is True
                    assert "vulnerabilities" in results["dummy"]
                    assert len(results["dummy"]["vulnerabilities"]) == 3
