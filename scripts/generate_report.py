#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Generate Report CLI
===================

Generate reports from existing audit results.

Usage:
    python scripts/generate_report.py reports/audit_result.json
    python scripts/generate_report.py reports/audit_result.json --format html pdf
"""

import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import click
from rich.console import Console

console = Console()


@click.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    multiple=True,
    type=click.Choice(["json", "html", "pdf", "csv"]),
    default=["html"],
    help="Output formats"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output directory (default: same as input)"
)
def main(input_file, format, output):
    """
    Generate reports from audit result file.
    
    Reads an existing JSON audit result and generates reports
    in specified formats.
    """
    console.print("[bold blue]📄 Report Generator[/bold blue]\n")
    
    input_path = Path(input_file)
    output_dir = Path(output) if output else input_path.parent
    
    # Load audit result
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    console.print(f"📂 Input: [cyan]{input_file}[/cyan]")
    console.print(f"📁 Output: [cyan]{output_dir}[/cyan]")
    console.print(f"📋 Formats: [cyan]{', '.join(format)}[/cyan]\n")
    
    base_name = input_path.stem
    
    for fmt in format:
        output_path = output_dir / f"{base_name}.{fmt}"
        
        if fmt == "html":
            generate_html(data, output_path)
        elif fmt == "csv":
            generate_csv(data, output_path)
        elif fmt == "json":
            # Copy with pretty print
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        
        console.print(f"✅ Generated: [green]{output_path}[/green]")
    
    console.print("\n[bold green]Done![/bold green]")


def generate_html(data, output_path):
    """Generate HTML report."""
    # Reuse HTML generation from orchestrator
    from src.orchestrator import AuditOrchestrator
    from src.models.audit_result import AuditResult, Severity, GateDecision, Vulnerability, ScanResult
    from datetime import datetime
    
    # Reconstruct minimal AuditResult for HTML generation
    orchestrator = AuditOrchestrator()
    
    # Build simple HTML
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Audit Report - {data.get('audit_id', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #007bff; color: white; }}
    </style>
</head>
<body>
    <h1>🛡️ Security Audit Report</h1>
    <div class="summary">
        <p><strong>Audit ID:</strong> {data.get('audit_id', 'N/A')}</p>
        <p><strong>Date:</strong> {data.get('audit_timestamp', 'N/A')}</p>
        <p><strong>Decision:</strong> {data.get('gate_decision', 'N/A')}</p>
        <p><strong>Reason:</strong> {data.get('gate_reason', 'N/A')}</p>
    </div>
    <h2>Summary</h2>
    <pre>{json.dumps(data.get('summary', {}), indent=2)}</pre>
</body>
</html>
    """
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def generate_csv(data, output_path):
    """Generate CSV report of vulnerabilities."""
    import csv
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "Severity", "Title", "File", "Line", 
            "Scanner", "CWE", "OWASP", "Remediation"
        ])
        
        for scan_result in data.get("scan_results", []):
            for vuln in scan_result.get("vulnerabilities", []):
                writer.writerow([
                    vuln.get("id", ""),
                    vuln.get("severity", ""),
                    vuln.get("title", ""),
                    vuln.get("file_path", ""),
                    vuln.get("line_number", ""),
                    vuln.get("scanner", ""),
                    vuln.get("cwe_id", ""),
                    vuln.get("owasp_id", ""),
                    vuln.get("remediation", ""),
                ])


if __name__ == "__main__":
    main()
