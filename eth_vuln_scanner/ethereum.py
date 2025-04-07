"""
Ethereum blockchain interaction functionality
"""

import json
import os
import tempfile
from pathlib import Path
import requests
from web3 import Web3
from web3.exceptions import ContractLogicError

class EthereumClient:
    """Client for interacting with the Ethereum blockchain"""

    def __init__(self, config):
        """
        Initialize the Ethereum client

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.w3 = Web3(Web3.HTTPProvider(config["rpc_url"]))

        # Check connection
        try:
            if not self.w3.is_connected():
                raise ConnectionError(f"Could not connect to Ethereum node at {config['rpc_url']}")
        except Exception as e:
            raise ConnectionError(f"Error connecting to Ethereum node at {config['rpc_url']}: {str(e)}")

        # Set up Etherscan API if available
        self.etherscan_api_key = config.get("etherscan_api_key") or config.get("api_key")
        self.etherscan_base_url = "https://api.etherscan.io/api"

    def get_contract_code(self, address):
        """
        Get the bytecode of a contract at the given address

        Args:
            address: Ethereum address of the contract

        Returns:
            str: Contract bytecode
        """
        # Validate address
        if not self.w3.is_address(address):
            raise ValueError(f"Invalid Ethereum address: {address}")

        # Normalize address
        address = self.w3.to_checksum_address(address)

        # Get bytecode
        bytecode = self.w3.eth.get_code(address).hex()

        # Check if contract exists
        if bytecode == "0x" or bytecode == "0x0":
            raise ValueError(f"No contract found at address {address}")

        return bytecode

    def get_contract_abi(self, address):
        """
        Get the ABI of a contract using Etherscan API

        Args:
            address: Ethereum address of the contract

        Returns:
            list: Contract ABI
        """
        if not self.etherscan_api_key:
            raise ValueError("Etherscan API key is required to fetch contract ABI")

        # Normalize address
        address = self.w3.to_checksum_address(address)

        # Make API request
        params = {
            "module": "contract",
            "action": "getabi",
            "address": address,
            "apikey": self.etherscan_api_key
        }

        response = requests.get(self.etherscan_base_url, params=params)
        data = response.json()

        if data["status"] != "1":
            raise ValueError(f"Failed to get ABI: {data.get('message', 'Unknown error')}")

        return json.loads(data["result"])

    def get_contract_source(self, address):
        """
        Get the source code of a contract using Etherscan API

        Args:
            address: Ethereum address of the contract

        Returns:
            dict: Contract source code information
        """
        # Use the provided API key for demonstration purposes if none is provided
        if not self.etherscan_api_key:
            self.etherscan_api_key = "KV5PG3YMC5KK53GVZDMDZXTETM22SQSF5C"  # Provided API key
            print(f"Using provided Etherscan API key")

        # Normalize address
        address = self.w3.to_checksum_address(address)

        # Make API request
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.etherscan_api_key
        }

        print(f"Fetching contract source code from Etherscan for address: {address}")
        print(f"API URL: {self.etherscan_base_url}")
        print(f"Params: {params}")

        response = requests.get(self.etherscan_base_url, params=params)
        print(f"Response status code: {response.status_code}")

        data = response.json()
        print(f"Response data: {data.get('message')}")

        if data["status"] != "1":
            raise ValueError(f"Failed to get source code: {data.get('message', 'Unknown error')}")

        return data["result"][0]

    def save_contract_source(self, address, output_dir=None):
        """
        Save the source code of a contract to a file

        Args:
            address: Ethereum address of the contract
            output_dir: Directory to save the source code (default: temporary directory)

        Returns:
            str: Path to the directory containing the source code
        """
        try:
            # Get source code
            source_info = self.get_contract_source(address)

            # Create output directory if not provided
            if output_dir is None:
                output_dir = tempfile.mkdtemp(prefix="eth_vuln_scanner_")
            else:
                output_dir = Path(output_dir)
                os.makedirs(output_dir, exist_ok=True)

            # Handle multiple source files (if contract is verified with multiple files)
            if source_info.get("SourceCode", "").startswith("{"):
                try:
                    # Try to parse as JSON
                    sources = json.loads(source_info["SourceCode"])

                    # Handle different Etherscan source code formats
                    if "sources" in sources:
                        # Standard JSON input format
                        for file_path, file_info in sources["sources"].items():
                            file_content = file_info["content"]
                            full_path = os.path.join(output_dir, file_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            with open(full_path, "w") as f:
                                f.write(file_content)
                    else:
                        # Multiple files format
                        for file_path, file_content in sources.items():
                            full_path = os.path.join(output_dir, file_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            with open(full_path, "w") as f:
                                f.write(file_content)
                except json.JSONDecodeError:
                    # Fall back to single file
                    contract_name = source_info.get("ContractName", "Contract")
                    with open(os.path.join(output_dir, f"{contract_name}.sol"), "w") as f:
                        f.write(source_info["SourceCode"])
            else:
                # Single source file
                contract_name = source_info.get("ContractName", "Contract")
                with open(os.path.join(output_dir, f"{contract_name}.sol"), "w") as f:
                    f.write(source_info["SourceCode"])

            return str(output_dir)
        except Exception as e:
            raise RuntimeError(f"Failed to fetch contract source code: {str(e)}")
