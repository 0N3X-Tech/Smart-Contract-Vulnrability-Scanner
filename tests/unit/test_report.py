"""
Unit tests for the report generation
"""

import json
import pytest
from eth_vuln_scanner.utils.report import generate_report

class TestReport:
    """Test the report generation"""
    
    @pytest.fixture
    def sample_results(self):
        """Return sample analysis results"""
        return {
            "dummy": {
                "success": True,
                "vulnerabilities": [
                    {
                        "title": "Test Vulnerability",
                        "severity": "High",
                        "description": "This is a test vulnerability",
                        "recommendation": "Fix the issue",
                        "code": "function test() { /* vulnerable code */ }",
                        "location": "Test.sol:42"
                    }
                ]
            }
        }
    
    def test_generate_text_report(self, sample_results):
        """Test generating a text report"""
        report = generate_report(sample_results, "0x1234567890123456789012345678901234567890", "text")
        
        # Check that the report contains the expected information
        assert "Ethereum Smart Contract Vulnerability Scan Report" in report
        assert "0x1234567890123456789012345678901234567890" in report
        assert "Test Vulnerability" in report
        assert "High" in report
        assert "This is a test vulnerability" in report
        assert "Fix the issue" in report
        assert "Test.sol:42" in report
    
    def test_generate_json_report(self, sample_results):
        """Test generating a JSON report"""
        report = generate_report(sample_results, "0x1234567890123456789012345678901234567890", "json")
        
        # Parse the JSON
        data = json.loads(report)
        
        # Check the structure
        assert "contract_address" in data
        assert data["contract_address"] == "0x1234567890123456789012345678901234567890"
        assert "scan_date" in data
        assert "results" in data
        assert "summary" in data
        assert data["summary"]["total_vulnerabilities"] == 1
        
        # Check the vulnerability details
        vuln = data["results"]["dummy"]["vulnerabilities"][0]
        assert vuln["title"] == "Test Vulnerability"
        assert vuln["severity"] == "High"
        assert vuln["description"] == "This is a test vulnerability"
    
    def test_generate_markdown_report(self, sample_results):
        """Test generating a Markdown report"""
        report = generate_report(sample_results, "0x1234567890123456789012345678901234567890", "markdown")
        
        # Check that the report contains the expected information
        assert "# Ethereum Smart Contract Vulnerability Scan Report" in report
        assert "0x1234567890123456789012345678901234567890" in report
        assert "## Summary" in report
        assert "| Analyzer | Vulnerabilities |" in report
        assert "## Detailed Findings" in report
        assert "### DUMMY" in report
        assert "#### 1. Test Vulnerability" in report
        assert "**Severity:** High" in report
        assert "**Description:** This is a test vulnerability" in report
        assert "**Recommendation:** Fix the issue" in report
        assert "```solidity" in report
