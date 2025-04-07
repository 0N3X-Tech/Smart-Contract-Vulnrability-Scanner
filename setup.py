from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name="eth_vuln_scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "eth-vuln-scanner=eth_vuln_scanner.cli:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A CLI tool for scanning Ethereum smart contracts for vulnerabilities",
    keywords="ethereum, security, smart contracts, vulnerability, scanner",
    python_requires=">=3.7",
)
