# Ethereum Smart Contract Vulnerability Scanner

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

A powerful command-line tool for scanning Ethereum smart contracts for security vulnerabilities. This tool connects to the Ethereum blockchain, fetches real smart contract source code, and analyzes it for common security issues.

## Features

- Fetch smart contracts from the Ethereum blockchain by address
- Discover and scan random verified contracts from Ethereum mainnet
- Analyze contracts using multiple vulnerability scanners:
  - Pattern Analyzer: Fast regex-based vulnerability detection
  - Slither: Static analysis for Solidity
  - Mythril: Symbolic execution for EVM bytecode
- Parallel execution for faster analysis of large contracts
- Comprehensive error handling and validation
- Automatic dependency detection and installation
- Generate detailed vulnerability reports in multiple formats (text, JSON, Markdown)
- Configurable through command-line options, environment variables, or config file

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Solidity compiler (for Slither analyzer)
- Node.js and npm (for Mythril analyzer)

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/eth-vuln-scanner.git
cd eth-vuln-scanner

# Install Python dependencies
pip install -r requirements.txt

# Install analyzer dependencies (optional)
./install_dependencies.sh
```

### Configuration

Create a `.env` file in the project root directory with your API keys:

```
# Ethereum RPC URLs
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY

# API Keys
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_API_KEY
INFURA_API_KEY=YOUR_INFURA_API_KEY

# Scanner Configuration
DEFAULT_TIMEOUT=300
DEFAULT_ANALYZERS=pattern,slither,mythril
```

## Usage

### Basic Usage

```bash
# Scan a specific contract
python -m eth_vuln_scanner.cli 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D

# Scan a random contract
python -m eth_vuln_scanner.cli --random

# Scan multiple random contracts
python -m eth_vuln_scanner.cli --multi-random 5

# Save report to a file
python -m eth_vuln_scanner.cli --random --output report.md --format markdown
```

### Command-Line Options

```
positional arguments:
  address               Ethereum smart contract address to scan

options:
  -h, --help            show this help message and exit
  --random              Scan a random verified contract from Ethereum mainnet
  --multi-random MULTI_RANDOM
                        Scan multiple random contracts (specify the number)

Connection Options:
  --rpc-url RPC_URL     Ethereum JSON-RPC URL (default: uses Infura mainnet)
  --api-key API_KEY     API key for Etherscan or Infura

Scan Options:
  --analyzers ANALYZERS
                        Comma-separated list of analyzers to use (default: all)
  --timeout TIMEOUT     Timeout for analysis in seconds (default: 300)
  --install-deps        Install missing dependencies without prompting

Output Options:
  --output OUTPUT       Output file for the report (default: stdout)
  --format {text,json,markdown}
                        Output format (text, json, markdown)
```

### Example Output

The tool provides detailed vulnerability reports with severity levels, descriptions, code snippets, and recommendations:

```
Ethereum Smart Contract Vulnerability Scan Report
=================================================

Contract Address: 0x7Be8076f4EA4A4AD08075C2508e481d6C946D12b
Scan Date: 2025-04-06 17:48:38

Summary:
--------
Total vulnerabilities found: 3
- pattern ✓: 2 vulnerabilities
- slither ✓: 1 vulnerabilities

Severity Summary:
----------------
| Severity | Count |
| -------- | ----- |
| High     | 1     |
| Medium   | 1     |
| Low      | 1     |
| Unknown  | 0     |

Detailed Findings:

High Severity Vulnerabilities (1)

1. Reentrancy Vulnerability (pattern)
Description: Potential reentrancy vulnerability detected. External calls are made before state changes.
Location: Contract.sol:42
Code:
   function withdraw(uint amount) public {
       require(balances[msg.sender] >= amount);
       (bool success, ) = msg.sender.call{value: amount}("");
       require(success);
       balances[msg.sender] -= amount;
   }
Recommendation: Follow the checks-effects-interactions pattern or use a reentrancy guard.
```

## Vulnerability Detection

The scanner detects various types of vulnerabilities, including:

### High Severity
- Reentrancy vulnerabilities
- Delegatecall to untrusted contracts
- Unprotected self-destruct functions

### Medium Severity
- Unchecked external calls
- Use of tx.origin for authentication

### Low Severity
- Timestamp dependence
- Inline assembly usage
- Floating pragma versions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Slither](https://github.com/crytic/slither) - Static analyzer for Solidity
- [Mythril](https://github.com/ConsenSys/mythril) - Security analysis tool for EVM bytecode
- [Web3.py](https://github.com/ethereum/web3.py) - Python interface for interacting with Ethereum
- [Rich](https://github.com/Textualize/rich) - Terminal formatting library

## Disclaimer

This tool is provided for educational and research purposes only. Always conduct a thorough security audit before deploying smart contracts to production. The authors are not responsible for any damages resulting from the use of this tool.
