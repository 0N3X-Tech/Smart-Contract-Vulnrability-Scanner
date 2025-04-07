"""
Module for finding random Ethereum smart contracts
"""

import random
import requests
import time
from web3 import Web3

class RandomContractFinder:
    """Utility for finding random Ethereum smart contracts"""

    def __init__(self, rpc_url, etherscan_api_key):
        """
        Initialize the random contract finder

        Args:
            rpc_url: Ethereum JSON-RPC URL
            etherscan_api_key: Etherscan API key
        """
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.etherscan_api_key = etherscan_api_key
        self.etherscan_base_url = "https://api.etherscan.io/api"

        # Check connection
        if not self.w3.is_connected():
            raise ConnectionError(f"Could not connect to Ethereum node at {rpc_url}")

    def get_latest_block_number(self):
        """
        Get the latest block number

        Returns:
            int: Latest block number
        """
        return self.w3.eth.block_number

    def get_random_block_number(self, min_block=1000000):
        """
        Get a random block number

        Args:
            min_block: Minimum block number to consider

        Returns:
            int: Random block number
        """
        latest_block = self.get_latest_block_number()
        return random.randint(min_block, latest_block)

    def get_contracts_from_block(self, block_number):
        """
        Get contract addresses from a block

        Args:
            block_number: Block number to get contracts from

        Returns:
            list: List of contract addresses
        """
        try:
            # Get block transactions
            block = self.w3.eth.get_block(block_number, full_transactions=True)

            # Find contract creation transactions (to address is None)
            contract_txs = [tx for tx in block.transactions if tx.get('to') is None]

            # Get contract addresses from transaction receipts
            contract_addresses = []
            for tx in contract_txs:
                try:
                    receipt = self.w3.eth.get_transaction_receipt(tx.hash)
                    if receipt.contractAddress:
                        contract_addresses.append(receipt.contractAddress)
                except Exception as e:
                    print(f"Error getting receipt for tx {tx.hash}: {str(e)}")

            return contract_addresses
        except Exception as e:
            print(f"Error getting contracts from block {block_number}: {str(e)}")
            return []

    def get_random_verified_contract(self):
        """
        Get a random verified contract from Etherscan

        Returns:
            str: Contract address
        """
        # List of popular contract addresses to try if API fails
        popular_contracts = [
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
            "0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5",  # Compound cETH
            "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
            "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"   # WBTC
        ]

        # Use Etherscan API to get a random verified contract
        try:
            # Try to get a random contract from a specific address range
            # This is more likely to find verified contracts
            for _ in range(3):
                # Generate a random address with a higher probability of being a contract
                # Focus on addresses that start with 0x0 to 0x9 (more likely to be contracts)
                prefix = random.choice(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"])
                address = "0x" + prefix + "".join(random.choice("0123456789abcdef") for _ in range(39))

                # Check if it's a verified contract
                if self.is_contract_verified(address):
                    return address

            # If that didn't work, try the Etherscan API to list verified contracts
            params = {
                "module": "contract",
                "action": "listverifiedcontracts",
                "page": random.randint(1, 20),  # Random page number
                "offset": 100,  # Max results per page
                "apikey": self.etherscan_api_key
            }

            response = requests.get(self.etherscan_base_url, params=params)
            data = response.json()

            if data["status"] == "1" and "result" in data:
                contracts = data["result"]
                if contracts:
                    # Pick a random contract from the results
                    contract = random.choice(contracts)
                    return contract["ContractAddress"]

            # If we still couldn't get a contract, try random blocks
            contract_address = self.get_random_contract_from_blocks()
            if contract_address:
                return contract_address

            # If all else fails, use a popular contract
            return random.choice(popular_contracts)

        except Exception as e:
            print(f"Error getting random verified contract: {str(e)}")
            # If there was an error, use a popular contract
            return random.choice(popular_contracts)

    def get_random_contract_from_blocks(self):
        """
        Get a random contract by scanning random blocks

        Returns:
            str: Contract address
        """
        # Try up to 5 random blocks
        for _ in range(5):
            block_number = self.get_random_block_number()
            print(f"Searching for contracts in block {block_number}...")

            contracts = self.get_contracts_from_block(block_number)
            if contracts:
                # Pick a random contract from the block
                return random.choice(contracts)

        # If we still couldn't find a contract, use a known contract
        print("Could not find a random contract, using a known contract...")
        return "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"  # Uniswap V2 Router

    def is_contract_verified(self, address):
        """
        Check if a contract is verified on Etherscan

        Args:
            address: Contract address

        Returns:
            bool: True if verified, False otherwise
        """
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.etherscan_api_key
        }

        try:
            response = requests.get(self.etherscan_base_url, params=params)
            data = response.json()

            if data["status"] == "1" and "result" in data:
                source_code = data["result"][0].get("SourceCode", "")
                return bool(source_code)

            return False
        except Exception as e:
            print(f"Error checking if contract is verified: {str(e)}")
            return False

    def find_random_verified_contract(self, max_attempts=5):
        """
        Find a random verified contract

        Args:
            max_attempts: Maximum number of attempts

        Returns:
            str: Contract address
        """
        print("Selecting a random verified contract...")

        # List of interesting contracts to choose from - focusing on contracts that might have vulnerabilities
        interesting_contracts = [
            # DeFi Protocols
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
            "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",  # Uniswap V2 Factory
            "0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5",  # Compound cETH
            "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B",  # Compound Comptroller
            "0x398eC7346DcD622eDc5ae82352F02bE94C62d119",  # Aave Lending Pool
            "0x24a42fD28C976A61Df5D00D0599C34c4f90748c8",  # Yearn Finance
            "0x9D25057e62939D3408406975aD75Ffe834DA4cDd",  # Yearn yETH vault
            "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643",  # Compound cDAI

            # NFT Marketplaces
            "0x7Be8076f4EA4A4AD08075C2508e481d6C946D12b",  # OpenSea Wyvern Exchange
            "0x7f268357A8c2552623316e2562D90e642bB538E5",  # OpenSea Wyvern Exchange v2

            # Older contracts (more likely to have vulnerabilities)
            "0x06012c8cf97BEaD5deAe237070F9587f8E7A266d",  # CryptoKitties
            "0x2af5d2ad76741191d15dfe7bf6ac92d4bd912ca3",  # LEO Token
            "0xB8c77482e45F1F44dE1745F52C74426C631bDD52",  # BNB Token

            # DAO contracts
            "0x9a8ab692a6d73242c74a727ac7587a7e635a3f2f",  # MakerDAO MCD_FLIP_ETH_A
            "0x35d1b3f3d7966a1dfe207aa4514c12a259a0492b",  # MakerDAO Vat

            # Flash loan contracts
            "0x398eC7346DcD622eDc5ae82352F02bE94C62d119",  # Aave Lending Pool
            "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",  # Aave V2 Lending Pool

            # Bridges (often targets for attacks)
            "0x3ee18B2214AFF97000D974cf647E7C347E8fa585",  # Wormhole Bridge
            "0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf",  # Polygon Bridge

            # Known exploited contracts (for educational purposes)
            "0x06A566E2bB119fB1a7d18c81B2a6a7828aB20efF",  # Parity Multisig Wallet (affected by the 2017 hack)
            "0xD4FE7BC31Cedb7BfB8A345F31E668033056B2728"   # PolyNetwork (hacked in 2021)
        ]

        # Pick a random contract from the list
        address = random.choice(interesting_contracts)
        print(f"Selected contract: {address}")

        return address
