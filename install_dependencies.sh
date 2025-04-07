#!/bin/bash
# Script to install dependencies for the Ethereum Smart Contract Vulnerability Scanner

echo "Installing dependencies for Ethereum Smart Contract Vulnerability Scanner..."

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    echo "Error: pip is not installed. Please install Python and pip first."
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install Slither
echo "Installing Slither..."
pip install slither-analyzer

# Install Mythril
echo "Installing Mythril..."
pip install mythril

# Install solc-select for Solidity compiler management
echo "Installing solc-select..."
pip install solc-select

# Install a few Solidity compiler versions
echo "Installing Solidity compiler versions..."
solc-select install 0.8.0
solc-select install 0.8.17
solc-select install 0.7.6
solc-select install 0.6.12
solc-select install 0.5.17

# Set default Solidity version
echo "Setting default Solidity version to 0.8.17..."
solc-select use 0.8.17

echo "Installation complete!"
echo "You can now use the Ethereum Smart Contract Vulnerability Scanner."
echo "Example: python -m eth_vuln_scanner.cli <ethereum_address>"
