#!/usr/bin/env python3
"""
Command-line interface for the Ethereum smart contract vulnerability scanner
"""

import argparse
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from eth_vuln_scanner.scanner import Scanner
from eth_vuln_scanner.utils.config import load_config
from eth_vuln_scanner.utils.dependency_checker import check_dependencies, install_dependencies
from eth_vuln_scanner.random_contract import RandomContractFinder

console = Console()

def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Scan Ethereum smart contracts for vulnerabilities"
    )

    # Main arguments
    parser.add_argument(
        "address",
        nargs="?",
        help="Ethereum smart contract address to scan"
    )

    parser.add_argument(
        "--random",
        action="store_true",
        help="Scan a random verified contract from Ethereum mainnet"
    )

    parser.add_argument(
        "--multi-random",
        type=int,
        help="Scan multiple random contracts (specify the number)"
    )

    # Connection options
    connection_group = parser.add_argument_group("Connection Options")
    connection_group.add_argument(
        "--rpc-url",
        help="Ethereum JSON-RPC URL (default: uses Infura mainnet)",
        default=None
    )
    connection_group.add_argument(
        "--api-key",
        help="API key for Etherscan or Infura",
        default=None
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--analyzers",
        help="Comma-separated list of analyzers to use (default: all)",
        default="pattern,slither,mythril"
    )
    scan_group.add_argument(
        "--timeout",
        help="Timeout for analysis in seconds (default: 300)",
        type=int,
        default=300
    )
    scan_group.add_argument(
        "--install-deps",
        help="Install missing dependencies without prompting",
        action="store_true"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output",
        help="Output file for the report (default: stdout)",
        default=None
    )
    output_group.add_argument(
        "--format",
        help="Output format (text, json, markdown)",
        choices=["text", "json", "markdown"],
        default="text"
    )

    return parser.parse_args()

def main():
    """Main entry point for the CLI"""
    args = parse_args()

    # Show banner
    console.print(
        Panel.fit(
            "[bold blue]Ethereum Smart Contract Vulnerability Scanner[/bold blue]",
            subtitle="v0.1.0"
        )
    )

    # Skip dependency check for demonstration
    console.print("[bold yellow]Note:[/bold yellow] Skipping dependency check for demonstration")

    # Check if address is provided or random/multi-random option is used
    if not args.address and not args.random and not args.multi_random:
        console.print("[bold red]Error:[/bold red] No Ethereum address provided and neither --random nor --multi-random specified")
        console.print("Usage: eth-vuln-scanner <ethereum_address> [options]")
        console.print("       eth-vuln-scanner --random [options]")
        console.print("       eth-vuln-scanner --multi-random <number> [options]")
        sys.exit(1)

    # Load configuration
    config = load_config(args)

    # Display configuration information
    console.print("[bold blue]Configuration:[/bold blue]")
    console.print(f"RPC URL: {config.get('rpc_url', 'Not set')}")

    etherscan_api_key = config.get('etherscan_api_key', '')
    if etherscan_api_key:
        masked_key = "*****" + etherscan_api_key[-4:] if len(etherscan_api_key) > 4 else "*****"
        console.print(f"Etherscan API Key: {masked_key}")
    else:
        console.print("Etherscan API Key: Not set")

    console.print(f"Analyzers: {', '.join(config.get('analyzers', []))}")
    console.print(f"Timeout: {config.get('timeout', 300)} seconds")

    # If random option is used, find a random contract
    if args.random:
        console.print("[bold]Finding a random verified contract to scan...[/bold]")
        try:
            # Initialize the random contract finder
            finder = RandomContractFinder(
                args.rpc_url or config.get("rpc_url"),
                args.api_key or config.get("etherscan_api_key") or config.get("api_key")
            )

            # Find a random verified contract
            address = finder.find_random_verified_contract()
            console.print(f"[bold green]Found random contract:[/bold green] {address}")
            args.address = address
        except Exception as e:
            console.print(f"[bold red]Error finding random contract:[/bold red] {str(e)}")
            sys.exit(1)

    # Check if RPC URL or API key is provided
    if not args.rpc_url and not args.api_key and "ETH_RPC_URL" not in os.environ and "INFURA_API_KEY" not in os.environ:
        console.print("[bold yellow]Warning:[/bold yellow] No RPC URL or API key provided")
        console.print("You need to provide either:")
        console.print("  - An Ethereum RPC URL with --rpc-url")
        console.print("  - An Infura API key with --api-key")
        console.print("  - Set the ETH_RPC_URL or INFURA_API_KEY environment variable")
        console.print("\nUsing a public Ethereum node for demonstration purposes only.")
        console.print("This may not work for all contracts and will be rate-limited.")

        # Use a public node for demonstration
        args.rpc_url = "https://eth.llamarpc.com"

    # Initialize scanner
    scanner = Scanner(config)

    # Handle multi-random scanning
    if args.multi_random:
        num_contracts = args.multi_random
        console.print(f"[bold]Scanning {num_contracts} random contracts[/bold]")

        # Initialize the random contract finder
        finder = RandomContractFinder(
            args.rpc_url or config.get("rpc_url"),
            args.api_key or config.get("etherscan_api_key") or config.get("api_key")
        )

        # Scan multiple contracts
        for i in range(num_contracts):
            try:
                # Find a random contract
                address = finder.find_random_verified_contract()
                console.print(f"\n[bold]Contract {i+1}/{num_contracts}:[/bold] {address}")

                # Generate output file name if needed
                output_file = None
                if args.output:
                    base, ext = os.path.splitext(args.output)
                    output_file = f"{base}_{i+1}{ext}"

                # Run the scan
                results = scanner.scan(address)

                # Check for errors in the metadata
                if "_metadata" in results and results["_metadata"].get("errors"):
                    errors = results["_metadata"]["errors"]
                    if errors:
                        console.print("[bold yellow]Warnings during analysis:[/bold yellow]")
                        for error in errors:
                            console.print(f"  - {error}")
                        console.print("")

                # Generate and display report
                if output_file:
                    scanner.save_report(results, output_file, args.format)
                    console.print(f"[green]Report saved to:[/green] {output_file}")
                else:
                    scanner.display_report(results, args.format)

            except Exception as e:
                console.print(f"[bold red]Error scanning contract {i+1}/{num_contracts}:[/bold red] {str(e)}")
                continue
    else:
        try:
            # Run the scan for a single contract
            console.print(f"[bold]Scanning contract at address:[/bold] {args.address}")
            results = scanner.scan(args.address)

            # Check for errors in the metadata
            if "_metadata" in results and results["_metadata"].get("errors"):
                errors = results["_metadata"]["errors"]
                if errors:
                    console.print("[bold yellow]Warnings during analysis:[/bold yellow]")
                    for error in errors:
                        console.print(f"  - {error}")
                    console.print("")

            # Generate and display report
            if args.output:
                scanner.save_report(results, args.output, args.format)
                console.print(f"[green]Report saved to:[/green] {args.output}")
            else:
                scanner.display_report(results, args.format)

        except ValueError as e:
            console.print(f"[bold red]Validation Error:[/bold red] {str(e)}")
            sys.exit(1)
        except ConnectionError as e:
            console.print(f"[bold red]Connection Error:[/bold red] {str(e)}")
            console.print("Please check your internet connection and RPC URL.")
            sys.exit(1)
        except RuntimeError as e:
            console.print(f"[bold red]Runtime Error:[/bold red] {str(e)}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Unexpected Error:[/bold red] {str(e)}")
            console.print("This is likely a bug in the tool. Please report it.")
            import traceback
            console.print("[dim]" + traceback.format_exc() + "[/dim]")
            sys.exit(1)

if __name__ == "__main__":
    main()
