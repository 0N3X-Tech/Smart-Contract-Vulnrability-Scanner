"""
Unit tests for the Ethereum client
"""

import os
import pytest
import tempfile
from unittest.mock import MagicMock, patch

from eth_vuln_scanner.ethereum import EthereumClient

class TestEthereumClient:
    """Test the Ethereum client"""
    
    def test_initialization(self, mock_config, mock_web3_provider):
        """Test initializing the Ethereum client"""
        with patch('eth_vuln_scanner.ethereum.Web3', return_value=mock_web3_provider):
            client = EthereumClient(mock_config)
            assert client.config == mock_config
            assert client.etherscan_api_key == mock_config["api_key"]
            assert client.etherscan_base_url == "https://api.etherscan.io/api"
    
    def test_get_contract_code(self, mock_config, mock_web3_provider):
        """Test getting contract bytecode"""
        with patch('eth_vuln_scanner.ethereum.Web3', return_value=mock_web3_provider):
            client = EthereumClient(mock_config)
            
            # Mock the get_code method
            mock_web3_provider.eth.get_code.return_value = bytes.fromhex('60806040')
            
            # Test getting contract code
            bytecode = client.get_contract_code("0x1234567890123456789012345678901234567890")
            assert bytecode == "0x60806040"
            
            # Test invalid address
            mock_web3_provider.is_address.return_value = False
            with pytest.raises(ValueError, match="Invalid Ethereum address"):
                client.get_contract_code("invalid_address")
            
            # Test non-existent contract
            mock_web3_provider.is_address.return_value = True
            mock_web3_provider.eth.get_code.return_value = bytes.fromhex('')
            with pytest.raises(ValueError, match="No contract found at address"):
                client.get_contract_code("0x1234567890123456789012345678901234567890")
    
    def test_get_contract_source_without_api_key(self, mock_config, mock_web3_provider):
        """Test getting contract source code without an API key"""
        with patch('eth_vuln_scanner.ethereum.Web3', return_value=mock_web3_provider):
            # Remove API key from config
            config = mock_config.copy()
            config.pop("api_key", None)
            
            client = EthereumClient(config)
            
            # Test getting contract source code
            source_info = client.get_contract_source("0x1234567890123456789012345678901234567890")
            assert source_info["ContractName"] == "DummyContract"
            assert "pragma solidity" in source_info["SourceCode"]
    
    @patch('eth_vuln_scanner.ethereum.requests.get')
    def test_get_contract_source_with_api_key(self, mock_get, mock_config, mock_web3_provider):
        """Test getting contract source code with an API key"""
        with patch('eth_vuln_scanner.ethereum.Web3', return_value=mock_web3_provider):
            client = EthereumClient(mock_config)
            
            # Mock the response from Etherscan
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "status": "1",
                "message": "OK",
                "result": [{
                    "ContractName": "TestContract",
                    "SourceCode": "pragma solidity ^0.8.0; contract TestContract {}"
                }]
            }
            mock_get.return_value = mock_response
            
            # Test getting contract source code
            source_info = client.get_contract_source("0x1234567890123456789012345678901234567890")
            assert source_info["ContractName"] == "TestContract"
            assert source_info["SourceCode"] == "pragma solidity ^0.8.0; contract TestContract {}"
            
            # Test API error
            mock_response.json.return_value = {
                "status": "0",
                "message": "Error",
                "result": ""
            }
            with pytest.raises(ValueError, match="Failed to get source code"):
                client.get_contract_source("0x1234567890123456789012345678901234567890")
    
    def test_save_contract_source(self, mock_config, mock_web3_provider, sample_contract_source):
        """Test saving contract source code to a file"""
        with patch('eth_vuln_scanner.ethereum.Web3', return_value=mock_web3_provider):
            client = EthereumClient(mock_config)
            
            # Mock the get_contract_source method
            client.get_contract_source = MagicMock(return_value={
                "ContractName": "TestContract",
                "SourceCode": sample_contract_source
            })
            
            # Test saving contract source code
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = client.save_contract_source("0x1234567890123456789012345678901234567890", temp_dir)
                assert output_dir == temp_dir
                
                # Check that the file was created
                contract_file = os.path.join(temp_dir, "TestContract.sol")
                assert os.path.exists(contract_file)
                
                # Check the file contents
                with open(contract_file, "r") as f:
                    content = f.read()
                    assert "pragma solidity" in content
                    assert "VulnerableContract" in content
