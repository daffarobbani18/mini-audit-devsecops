#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Run Audit CLI
=============

Command-line interface for running security audits.

Usage:
    python scripts/run_audit.py ./src
    python scripts/run_audit.py ./src --config gate_config.yaml
    python scripts/run_audit.py ./src --output reports --format json html
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from src.orchestrator import AuditOrchestrator


console = Console()


@click.command()
@click.argument("target_path", type=click.Path(exists=True))
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file (gate_config.yaml)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="reports",
    help="Output directory for reports"
)
@click.option(
    "--format", "-f",
    multiple=True,
    type=click.Choice(["json", "html"]),
    default=["json"],
    help="Output formats"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output"
)
@click.option(
    "--no-report",
    is_flag=True,
    help="Skip report generation"
)
def main(target_path, config, output, format, verbose, no_report):
    """
    Run security audit on TARGET_PATH.
    
    Scans Python code using Bandit (SAST) and checks dependencies
    using Safety (SCA). Returns exit code 1 if security gate fails.
    
    \b
    Examples:
        python run_audit.py ./src
        python run_audit.py ./my_project --config custom_config.yaml
        python run_audit.py . --format json html --output ./my_reports
    """
    console.print(Panel.fit(
        "[bold blue]🛡️ DevSecOps Security Audit[/bold blue]\n"
        "[dim]Automated Security Analysis Tool[/dim]",
        border_style="blue"
    ))

    console.print(f"\n📂 Target: [cyan]{target_path}[/cyan]")

    if config:
        console.print(f"⚙️  Config: [cyan]{config}[/cyan]")

    console.print()

    # Initialize orchestrator
    orchestrator = AuditOrchestrator(
        config_path=config,
        output_dir=output
    )

    # Check scanner availability
    with console.status("[bold green]Checking scanners..."):
        scanner_status = orchestrator.gate.check_scanners()

    # Display scanner status
    scanner_table = Table(title="Scanner Status", box=box.ROUNDED)
    scanner_table.add_column("Scanner", style="cyan")
    scanner_table.add_column("Status", style="green")
    scanner_table.add_column("Version")

    for name, status in scanner_status.items():
        status_str = "✅ Available" if status["available"] else "❌ Not Found"
        scanner_table.add_row(name, status_str, status["version"])

    console.print(scanner_table)
    console.print()

    # Run audit
    with console.status("[bold green]Running security scan..."):
        result = orchestrator.run_full_audit(target_path)

    # Display results
    display_results(result, verbose)

    # Save report
    if not no_report:
        with console.status("[bold green]Generating reports..."):
            saved_files = orchestrator.save_report(result, list(format))

        console.print("\n📄 [bold]Reports saved:[/bold]")
        for fmt, path in saved_files.items():
            console.print(f"   - {fmt.upper()}: [cyan]{path}[/cyan]")

    # Exit with appropriate code
    console.print()
    if result.passed:
        console.print(Panel(
            f"[bold green]✅ SECURITY GATE PASSED[/bold green]\n{result.gate_reason}",
            border_style="green"
        ))
        sys.exit(0)
    else:
        console.print(Panel(
            f"[bold red]❌ SECURITY GATE FAILED[/bold red]\n{result.gate_reason}",
            border_style="red"
        ))
        sys.exit(1)


def display_results(result, verbose):
    """Display audit results in a formatted table."""
    # Summary table
    summary_table = Table(title="Audit Summary", box=box.ROUNDED)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Audit ID", result.audit_id)
    summary_table.add_row("Timestamp", result.audit_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    summary_table.add_row("🔴 Critical", str(result.critical_count))
    summary_table.add_row("🟠 High", str(result.high_count))
    summary_table.add_row("🟡 Medium", str(result.medium_count))
    summary_table.add_row("🟢 Low", str(result.low_count))
    summary_table.add_row("📊 Total Score", str(result.total_score))
    summary_table.add_row(
        "Gate Decision",
        f"[{'green' if result.passed else 'red'}]{result.gate_decision.value}[/]"
    )

    console.print(summary_table)

    # Vulnerability details
    if result.all_vulnerabilities:
        console.print()
        vuln_table = Table(title="Vulnerability Details", box=box.ROUNDED)
        vuln_table.add_column("Severity", style="bold")
        vuln_table.add_column("Title", max_width=40)
        vuln_table.add_column("Location", max_width=30)
        vuln_table.add_column("Scanner")

        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "green",
            "INFO": "dim",
        }

        for vuln in result.all_vulnerabilities[:20]:  # Limit to 20
            color = severity_colors.get(vuln.severity.value, "white")
            location = f"{vuln.file_path}:{vuln.line_number}" if vuln.file_path else "N/A"
            vuln_table.add_row(
                f"[{color}]{vuln.severity.emoji} {vuln.severity.value}[/]",
                vuln.title[:40],
                location[:30],
                vuln.scanner
            )

        console.print(vuln_table)

        if len(result.all_vulnerabilities) > 20:
            console.print(f"[dim]... and {len(result.all_vulnerabilities) - 20} more[/dim]")


if __name__ == "__main__":
    main()
