"""
Report generation utilities
"""

import json
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def generate_text_report(results, contract_address):
    """
    Generate a text report from scan results

    Args:
        results: Scan results dictionary
        contract_address: Ethereum address of the contract

    Returns:
        str: Text report
    """
    report = []

    # Extract metadata if available
    metadata = results.get("_metadata", {})
    if metadata and "contract_address" in metadata:
        contract_address = metadata["contract_address"]

    # Header
    report.append(f"Ethereum Smart Contract Vulnerability Scan Report")
    report.append(f"=================================================")
    report.append("")
    report.append(f"Contract Address: {contract_address}")
    report.append(f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    # Summary
    total_vulnerabilities = sum(len(analyzer_results.get("vulnerabilities", []))
                               for name, analyzer_results in results.items()
                               if name != "_metadata")

    report.append(f"Summary:")
    report.append(f"--------")
    report.append(f"Total vulnerabilities found: {total_vulnerabilities}")

    # Add analyzer statistics
    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue
        vulns = analyzer_results.get("vulnerabilities", [])
        status = "✓" if analyzer_results.get("success", True) else "✗"
        report.append(f"- {analyzer} {status}: {len(vulns)} vulnerabilities")

    # Add errors if any
    if metadata and metadata.get("errors"):
        report.append("\nWarnings/Errors:")
        report.append("----------------")
        for error in metadata["errors"]:
            report.append(f"- {error}")

    report.append("")

    # Detailed findings
    report.append(f"Detailed Findings:")
    report.append(f"-----------------")

    for analyzer, analyzer_results in results.items():
        report.append(f"\n[{analyzer.upper()}]")

        vulnerabilities = analyzer_results.get("vulnerabilities", [])
        if not vulnerabilities:
            report.append("No vulnerabilities found.")
            continue

        for i, vuln in enumerate(vulnerabilities, 1):
            report.append(f"\n{i}. {vuln.get('title', 'Unnamed Vulnerability')}")
            report.append(f"   Severity: {vuln.get('severity', 'Unknown')}")
            report.append(f"   Description: {vuln.get('description', 'No description')}")

            if "location" in vuln:
                report.append(f"   Location: {vuln['location']}")

            if "code" in vuln:
                report.append(f"   Code:")
                report.append(f"   ```")
                for line in vuln["code"].split("\n"):
                    report.append(f"   {line}")
                report.append(f"   ```")

            if "recommendation" in vuln:
                report.append(f"   Recommendation: {vuln['recommendation']}")

    return "\n".join(report)

def generate_json_report(results, contract_address):
    """
    Generate a JSON report from scan results

    Args:
        results: Scan results dictionary
        contract_address: Ethereum address of the contract

    Returns:
        str: JSON report
    """
    # Extract metadata if available
    metadata = results.get("_metadata", {})
    if metadata and "contract_address" in metadata:
        contract_address = metadata["contract_address"]

    # Collect all vulnerabilities and categorize by severity
    all_vulnerabilities = []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    severity_vulnerabilities = {"High": [], "Medium": [], "Low": [], "Unknown": []}

    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue

        for vuln in analyzer_results.get("vulnerabilities", []):
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Add analyzer name to the vulnerability
            vuln_with_source = vuln.copy()
            vuln_with_source["analyzer"] = analyzer

            # Add to the appropriate severity category
            severity_vulnerabilities[severity].append(vuln_with_source)

            # Add to the overall list
            all_vulnerabilities.append(vuln_with_source)

    total_vulnerabilities = sum(severity_counts.values())

    # Create analyzer summary
    analyzer_summary = {}
    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue
        analyzer_summary[analyzer] = {
            "vulnerabilities": len(analyzer_results.get("vulnerabilities", [])),
            "success": analyzer_results.get("success", True),
            "error": analyzer_results.get("error", None)
        }

    report = {
        "contract_address": contract_address,
        "scan_date": datetime.datetime.now().isoformat(),
        "results": results,
        "summary": {
            "total_vulnerabilities": total_vulnerabilities,
            "analyzers": analyzer_summary,
            "severity": severity_counts,
            "errors": metadata.get("errors", [])
        },
        "vulnerabilities_by_severity": severity_vulnerabilities,
        "all_vulnerabilities": all_vulnerabilities
    }

    return json.dumps(report, indent=2)

def generate_markdown_report(results, contract_address):
    """
    Generate a Markdown report from scan results

    Args:
        results: Scan results dictionary
        contract_address: Ethereum address of the contract

    Returns:
        str: Markdown report
    """
    report = []

    # Extract metadata if available
    metadata = results.get("_metadata", {})
    if metadata and "contract_address" in metadata:
        contract_address = metadata["contract_address"]

    # Header
    report.append("# Ethereum Smart Contract Vulnerability Scan Report")
    report.append("")
    report.append(f"**Contract Address:** {contract_address}")
    report.append(f"**Scan Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")

    # Collect all vulnerabilities and categorize by severity
    all_vulnerabilities = []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    severity_vulnerabilities = {"High": [], "Medium": [], "Low": [], "Unknown": []}

    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue

        for vuln in analyzer_results.get("vulnerabilities", []):
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Add analyzer name to the vulnerability
            vuln_with_source = vuln.copy()
            vuln_with_source["analyzer"] = analyzer

            # Add to the appropriate severity category
            severity_vulnerabilities[severity].append(vuln_with_source)

            # Add to the overall list
            all_vulnerabilities.append(vuln_with_source)

    total_vulnerabilities = sum(severity_counts.values())

    # Summary
    report.append("## Summary")
    report.append("")
    report.append(f"**Total vulnerabilities found:** {total_vulnerabilities}")
    report.append("")
    report.append("| Analyzer | Status | Vulnerabilities |")
    report.append("| -------- | ------ | --------------- |")
    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue
        vulns = analyzer_results.get("vulnerabilities", [])
        status = "✓" if analyzer_results.get("success", True) else "✗"
        report.append(f"| {analyzer} | {status} | {len(vulns)} |")
    report.append("")

    # Severity summary
    report.append("## Severity Summary")
    report.append("")
    report.append("| Severity | Count |")
    report.append("| -------- | ----- |")
    for severity, count in severity_counts.items():
        report.append(f"| {severity} | {count} |")
    report.append("")

    # Add errors if any
    if metadata and metadata.get("errors"):
        report.append("## Warnings/Errors")
        report.append("")
        for error in metadata["errors"]:
            report.append(f"- {error}")
        report.append("")

    # Detailed findings
    report.append("## Detailed Findings")

    # Group vulnerabilities by severity
    for severity_level in ["High", "Medium", "Low", "Unknown"]:
        count = severity_counts.get(severity_level, 0)
        if count > 0:
            report.append(f"\n### {severity_level} Severity Vulnerabilities ({count})")

            # Find vulnerabilities with this severity
            severity_vulns = severity_vulnerabilities.get(severity_level, [])

            for i, vuln in enumerate(severity_vulns, 1):
                analyzer = vuln.get("analyzer", "Unknown")
                report.append(f"\n#### {i}. {vuln.get('title', 'Unnamed Vulnerability')} ({analyzer})")
                report.append(f"**Description:** {vuln.get('description', 'No description')}")

                if "location" in vuln:
                    report.append(f"**Location:** {vuln['location']}")

                if "code" in vuln:
                    report.append(f"**Code:**")
                    report.append("```solidity")
                    report.append(vuln["code"])
                    report.append("```")

                if "recommendation" in vuln:
                    report.append(f"**Recommendation:** {vuln['recommendation']}")

    # Show analyzers with no vulnerabilities
    report.append("\n### Analyzers with No Vulnerabilities")
    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue

        vulnerabilities = analyzer_results.get("vulnerabilities", [])
        if not vulnerabilities:
            report.append(f"- {analyzer}")

    return "\n".join(report)

def display_report_rich(results, contract_address):
    """
    Display a report using rich formatting

    Args:
        results: Scan results dictionary
        contract_address: Ethereum address of the contract
    """
    # Extract metadata if available
    metadata = results.get("_metadata", {})
    if metadata and "contract_address" in metadata:
        contract_address = metadata["contract_address"]

    # Header
    console.print(Panel.fit(
        f"[bold]Ethereum Smart Contract Vulnerability Scan Report[/bold]\n\n"
        f"Contract Address: [cyan]{contract_address}[/cyan]\n"
        f"Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="Scan Report",
        border_style="blue"
    ))

    # Collect all vulnerabilities and categorize by severity
    all_vulnerabilities = []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}

    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue

        for vuln in analyzer_results.get("vulnerabilities", []):
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            all_vulnerabilities.append((analyzer, vuln))

    total_vulnerabilities = sum(severity_counts.values())

    # Summary
    console.print("\n[bold]Summary:[/bold]")

    summary_table = Table(show_header=True, header_style="bold")
    summary_table.add_column("Analyzer")
    summary_table.add_column("Vulnerabilities", justify="right")

    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue
        vulns = analyzer_results.get("vulnerabilities", [])
        summary_table.add_row(analyzer, str(len(vulns)))

    summary_table.add_row("Total", str(total_vulnerabilities), style="bold")
    console.print(summary_table)

    # Severity summary
    console.print("\n[bold]Severity Summary:[/bold]")

    severity_table = Table(show_header=True, header_style="bold")
    severity_table.add_column("Severity")
    severity_table.add_column("Count", justify="right")

    severity_colors = {
        "High": "red",
        "Medium": "yellow",
        "Low": "green",
        "Unknown": "white"
    }

    for severity, count in severity_counts.items():
        color = severity_colors.get(severity, "white")
        severity_table.add_row(f"[{color}]{severity}[/{color}]", str(count))

    console.print(severity_table)

    # Detailed findings
    console.print("\n[bold]Detailed Findings:[/bold]")

    # First show high severity vulnerabilities
    for severity_level in ["High", "Medium", "Low", "Unknown"]:
        color = severity_colors.get(severity_level, "white")
        count = severity_counts.get(severity_level, 0)

        if count > 0:
            console.print(f"\n[bold {color}]{severity_level} Severity Vulnerabilities ({count})[/bold {color}]")

            # Find vulnerabilities with this severity
            severity_vulns = [(a, v) for a, v in all_vulnerabilities if v.get("severity", "Unknown") == severity_level]

            for i, (analyzer, vuln) in enumerate(severity_vulns, 1):
                console.print(f"\n[bold]{i}. {vuln.get('title', 'Unnamed Vulnerability')}[/bold] [dim]({analyzer})[/dim]")
                console.print(f"Description: {vuln.get('description', 'No description')}")

                if "location" in vuln:
                    console.print(f"Location: {vuln['location']}")

                if "code" in vuln:
                    console.print("Code:")
                    console.print(Panel(vuln["code"], border_style="dim"))

                if "recommendation" in vuln:
                    console.print(f"Recommendation: {vuln['recommendation']}")

    # Show analyzers with no vulnerabilities
    console.print("\n[bold]Analyzers with No Vulnerabilities:[/bold]")
    for analyzer, analyzer_results in results.items():
        if analyzer == "_metadata":
            continue

        vulnerabilities = analyzer_results.get("vulnerabilities", [])
        if not vulnerabilities:
            console.print(f"- {analyzer}")

def generate_report(results, contract_address, format_type="text"):
    """
    Generate a report from scan results

    Args:
        results: Scan results dictionary
        contract_address: Ethereum address of the contract
        format_type: Report format (text, json, markdown)

    Returns:
        str: Report in the specified format
    """
    if format_type == "json":
        return generate_json_report(results, contract_address)
    elif format_type == "markdown":
        return generate_markdown_report(results, contract_address)
    else:  # Default to text
        return generate_text_report(results, contract_address)
