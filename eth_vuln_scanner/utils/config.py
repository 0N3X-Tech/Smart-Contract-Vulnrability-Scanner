"""
Configuration handling for the Ethereum smart contract vulnerability scanner
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get configuration from environment variables
DEFAULT_CONFIG = {
    "rpc_url": os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com"),
    "analyzers": os.getenv("DEFAULT_ANALYZERS", "pattern,slither,mythril").split(","),
    "etherscan_api_key": os.getenv("ETHERSCAN_API_KEY", ""),
    "infura_api_key": os.getenv("INFURA_API_KEY", ""),
    "timeout": int(os.getenv("DEFAULT_TIMEOUT", "300")),
    "output_format": "text",
}

def load_config(args):
    """
    Load configuration from config file and command-line arguments

    Args:
        args: Command-line arguments

    Returns:
        dict: Configuration dictionary
    """
    # Start with default config (which already includes env vars from .env)
    config = DEFAULT_CONFIG.copy()

    # Load from config file if it exists (lowest priority)
    config_file = Path.home() / ".eth_vuln_scanner.json"
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                file_config = json.load(f)
                config.update(file_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load config file: {e}")

    # Override with command-line arguments (highest priority)
    if args.rpc_url:
        config["rpc_url"] = args.rpc_url
    if args.api_key:
        config["etherscan_api_key"] = args.api_key
    if args.analyzers:
        config["analyzers"] = args.analyzers.split(",")
    if args.timeout:
        config["timeout"] = args.timeout
    if args.format:
        config["output_format"] = args.format

    # Print configuration summary (without sensitive info)
    config_summary = config.copy()
    if "etherscan_api_key" in config_summary and config_summary["etherscan_api_key"]:
        config_summary["etherscan_api_key"] = "*****" + config_summary["etherscan_api_key"][-4:] if len(config_summary["etherscan_api_key"]) > 4 else "*****"
    if "infura_api_key" in config_summary and config_summary["infura_api_key"]:
        config_summary["infura_api_key"] = "*****" + config_summary["infura_api_key"][-4:] if len(config_summary["infura_api_key"]) > 4 else "*****"
    if "rpc_url" in config_summary and config_summary["rpc_url"]:
        # Mask API keys in RPC URLs
        rpc_url = config_summary["rpc_url"]
        if "/v2/" in rpc_url and len(rpc_url.split("/v2/")) > 1:
            base_url = rpc_url.split("/v2/")[0]
            config_summary["rpc_url"] = f"{base_url}/v2/*****"

    # If we have an Infura API key but no full URL, construct it
    if "infura_api_key" in config and config["infura_api_key"] and not config["rpc_url"].startswith("http"):
        config["rpc_url"] = f"https://mainnet.infura.io/v3/{config['infura_api_key']}"

    return config

def save_config(config, path=None):
    """
    Save configuration to a file

    Args:
        config: Configuration dictionary
        path: Path to save the config file (default: ~/.eth_vuln_scanner.json)
    """
    if path is None:
        path = Path.home() / ".eth_vuln_scanner.json"

    # Don't save sensitive information
    save_config = {k: v for k, v in config.items() if k not in ["api_key", "infura_api_key", "etherscan_api_key"]}

    try:
        with open(path, "w") as f:
            json.dump(save_config, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save config file: {e}")
