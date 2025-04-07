"""
Core scanning functionality for the Ethereum smart contract vulnerability scanner
"""

import os
import time
import tempfile
from pathlib import Path

from eth_vuln_scanner.ethereum import EthereumClient
from eth_vuln_scanner.analyzers.slither_analyzer import SlitherAnalyzer
from eth_vuln_scanner.analyzers.mythril_analyzer import MythrilAnalyzer
from eth_vuln_scanner.analyzers.pattern_analyzer import PatternAnalyzer
from eth_vuln_scanner.utils.report import generate_report, display_report_rich
from eth_vuln_scanner.utils.performance import timeit, parallel_analyze

class Scanner:
    """Main scanner class that coordinates the analysis process"""

    def __init__(self, config):
        """
        Initialize the scanner

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.ethereum_client = EthereumClient(config)

        # Initialize analyzers based on configuration
        self.analyzers = {}
        analyzers_config = config.get("analyzers", [])

        # Always add the pattern analyzer (it has no external dependencies)
        self.analyzers["pattern"] = PatternAnalyzer(config)
        print("Using pattern analyzer for basic vulnerability detection")

        # Try to initialize Slither if requested or if no specific analyzers are specified
        if "slither" in analyzers_config or not analyzers_config:
            try:
                self.analyzers["slither"] = SlitherAnalyzer(config)
                print("Successfully initialized Slither analyzer")
            except RuntimeError as e:
                print(f"Warning: Could not initialize Slither analyzer: {e}")

        # Try to initialize Mythril if requested or if no specific analyzers are specified
        if "mythril" in analyzers_config or not analyzers_config:
            try:
                self.analyzers["mythril"] = MythrilAnalyzer(config)
                print("Successfully initialized Mythril analyzer")
            except RuntimeError as e:
                print(f"Warning: Could not initialize Mythril analyzer: {e}")

        # Ensure we have at least the pattern analyzer
        if not self.analyzers:
            print("Warning: No analyzers could be initialized. Using pattern analyzer only.")
            self.analyzers["pattern"] = PatternAnalyzer(config)

    @timeit
    def scan(self, contract_address):
        """
        Scan a contract for vulnerabilities

        Args:
            contract_address: Ethereum address of the contract

        Returns:
            dict: Scan results from all analyzers
        """
        # Validate the contract address
        if not contract_address or not isinstance(contract_address, str):
            raise ValueError("Contract address must be a non-empty string")

        # Basic format validation for Ethereum addresses
        if not contract_address.startswith("0x") or len(contract_address) != 42:
            raise ValueError(f"Invalid Ethereum address format: {contract_address}")

        # Store the contract address in the config
        self.config["contract_address"] = contract_address

        # Fetch contract source code
        try:
            contract_dir = self.ethereum_client.save_contract_source(contract_address)
        except Exception as e:
            raise RuntimeError(f"Failed to fetch contract source code: {str(e)}")

        # Run analyzers in parallel
        start_time = time.time()
        print(f"Starting analysis with {len(self.analyzers)} analyzers...")

        # Use parallel execution if there are multiple analyzers
        if len(self.analyzers) > 1:
            results = parallel_analyze(self.analyzers, contract_dir)
        else:
            # Run single analyzer directly
            name = next(iter(self.analyzers))
            analyzer = self.analyzers[name]
            try:
                results = {name: analyzer.analyze(contract_dir)}
            except Exception as e:
                results = {name: {
                    "success": False,
                    "error": f"Analyzer failed: {str(e)}",
                    "vulnerabilities": []
                }}

        # Validate and normalize results
        analyzer_errors = []
        for name, result in results.items():
            try:
                # Validate the analyzer results
                if not isinstance(result, dict):
                    raise TypeError(f"Analyzer {name} returned invalid result type: {type(result)}")

                if "success" not in result:
                    result["success"] = True

                if "vulnerabilities" not in result:
                    result["vulnerabilities"] = []

            except Exception as e:
                analyzer_errors.append(f"{name}: {str(e)}")
                results[name] = {
                    "success": False,
                    "error": f"Analyzer failed: {str(e)}",
                    "vulnerabilities": []
                }

        end_time = time.time()
        print(f"Analysis completed in {end_time - start_time:.2f} seconds")

        # Add metadata to the results
        results["_metadata"] = {
            "contract_address": contract_address,
            "analyzer_count": len(self.analyzers),
            "successful_analyzers": sum(1 for name, result in results.items()
                                      if name != "_metadata" and result.get("success", False)),
            "errors": analyzer_errors
        }

        return results

    def display_report(self, results, format_type="text"):
        """
        Display a report of the scan results

        Args:
            results: Scan results dictionary
            format_type: Report format (text, json, markdown)
        """
        if format_type == "text":
            # Use rich formatting for terminal output
            display_report_rich(results, self.config.get("contract_address", "Unknown"))
        else:
            # Generate and print the report
            report = generate_report(results, self.config.get("contract_address", "Unknown"), format_type)
            print(report)

    def save_report(self, results, output_file, format_type="text"):
        """
        Save a report of the scan results to a file

        Args:
            results: Scan results dictionary
            output_file: Path to the output file
            format_type: Report format (text, json, markdown)
        """
        report = generate_report(results, self.config.get("contract_address", "Unknown"), format_type)

        with open(output_file, "w") as f:
            f.write(report)
