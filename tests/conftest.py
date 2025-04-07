"""
Pytest configuration for the Ethereum smart contract vulnerability scanner tests
"""

import os
import pytest
from pathlib import Path

# Add the project root to the Python path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def sample_contract_dir():
    """Return the path to the sample contracts directory"""
    return os.path.join(os.path.dirname(__file__), 'data', 'contracts')

@pytest.fixture
def sample_contract_source():
    """Return a sample contract source code"""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;
    
    contract VulnerableContract {
        mapping(address => uint256) private balances;
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
        
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] -= amount;
        }
        
        function getBalance() public view returns (uint256) {
            return balances[msg.sender];
        }
    }
    """

@pytest.fixture
def mock_web3_provider():
    """Return a mock Web3 provider"""
    from unittest.mock import MagicMock
    from web3 import Web3
    
    # Create a mock provider
    mock_provider = MagicMock()
    mock_provider.is_connected.return_value = True
    
    # Create a Web3 instance with the mock provider
    w3 = Web3(mock_provider)
    
    # Mock the to_checksum_address method
    w3.to_checksum_address = lambda addr: addr
    
    # Mock the get_code method
    w3.eth.get_code = MagicMock(return_value=bytes.fromhex('60806040'))
    
    return w3

@pytest.fixture
def mock_config():
    """Return a mock configuration"""
    return {
        "rpc_url": "https://mock-rpc-url.example.com",
        "analyzers": ["slither", "mythril"],
        "timeout": 30,
        "output_format": "text",
        "api_key": "mock-api-key"
    }
