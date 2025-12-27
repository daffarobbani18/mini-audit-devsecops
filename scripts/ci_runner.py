#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CI Runner - Entry Point for CI/CD Pipelines
============================================

Specialized script for running security audits in CI/CD environments.
Provides machine-readable output and proper exit codes for pipeline integration.

Features:
- CI-optimized output (minimal, parseable)
- Summary JSON generation for pipeline consumption
- Proper exit codes (0=pass, 1=fail, 2=error)
- GitHub Actions compatible
- GitLab CI compatible
- Azure DevOps compatible

Usage:
    python scripts/ci_runner.py --target ./src --output ./reports --ci-mode
    python scripts/ci_runner.py --target . --format json --ci-mode
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import click

from src.config import load_config
from src.gate.security_gate import SecurityGate
from src.orchestrator import AuditOrchestrator
from src.models.audit_result import GateDecision


def is_ci_environment() -> bool:
    """Detect if running in a CI environment."""
    ci_indicators = [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI", 
        "JENKINS_URL",
        "AZURE_PIPELINES",
        "CIRCLECI",
        "TRAVIS",
        "BITBUCKET_PIPELINES",
    ]
    return any(os.environ.get(var) for var in ci_indicators)


def get_ci_info() -> dict:
    """Get CI environment information."""
    info = {
        "ci_platform": "unknown",
        "commit_sha": None,
        "branch": None,
        "pr_number": None,
        "run_id": None,
    }
    
    # GitHub Actions
    if os.environ.get("GITHUB_ACTIONS"):
        info["ci_platform"] = "github_actions"
        info["commit_sha"] = os.environ.get("GITHUB_SHA")
        info["branch"] = os.environ.get("GITHUB_REF_NAME")
        info["pr_number"] = os.environ.get("GITHUB_PR_NUMBER")
        info["run_id"] = os.environ.get("GITHUB_RUN_ID")
        
    # GitLab CI
    elif os.environ.get("GITLAB_CI"):
        info["ci_platform"] = "gitlab_ci"
        info["commit_sha"] = os.environ.get("CI_COMMIT_SHA")
        info["branch"] = os.environ.get("CI_COMMIT_REF_NAME")
        info["pr_number"] = os.environ.get("CI_MERGE_REQUEST_IID")
        info["run_id"] = os.environ.get("CI_PIPELINE_ID")
        
    # Azure DevOps
    elif os.environ.get("AZURE_PIPELINES") or os.environ.get("TF_BUILD"):
        info["ci_platform"] = "azure_devops"
        info["commit_sha"] = os.environ.get("BUILD_SOURCEVERSION")
        info["branch"] = os.environ.get("BUILD_SOURCEBRANCHNAME")
        info["pr_number"] = os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID")
        info["run_id"] = os.environ.get("BUILD_BUILDID")
        
    return info


def print_ci_log(message: str, level: str = "info"):
    """Print log message in CI-compatible format."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # GitHub Actions grouping
    if os.environ.get("GITHUB_ACTIONS"):
        if level == "group_start":
            print(f"::group::{message}")
        elif level == "group_end":
            print("::endgroup::")
        elif level == "error":
            print(f"::error::{message}")
        elif level == "warning":
            print(f"::warning::{message}")
        else:
            print(f"[{timestamp}] {message}")
    else:
        # Standard output
        prefix = {"error": "ERROR", "warning": "WARN", "info": "INFO"}.get(level, "INFO")
        print(f"[{timestamp}] [{prefix}] {message}")


@click.command()
@click.option(
    "--target", "-t",
    type=click.Path(exists=True),
    default=".",
    help="Target path to scan"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="reports",
    help="Output directory for reports"
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file"
)
@click.option(
    "--format", "-f",
    multiple=True,
    type=click.Choice(["json", "html", "sarif"]),
    default=["json"],
    help="Output formats"
)
@click.option(
    "--ci-mode",
    is_flag=True,
    default=False,
    help="Enable CI mode (minimal output, machine-readable)"
)
@click.option(
    "--full-scan",
    is_flag=True,
    default=False,
    help="Run comprehensive scan (slower, more thorough)"
)
@click.option(
    "--fail-on-warning",
    is_flag=True,
    default=False,
    help="Fail pipeline on WARNING (not just FAILED)"
)
@click.option(
    "--output-summary",
    type=click.Path(),
    help="Path to write summary JSON (for CI consumption)"
)
def main(target, output, config, format, ci_mode, full_scan, fail_on_warning, output_summary):
    """
    Run security audit optimized for CI/CD pipelines.
    
    Exit Codes:
        0 - Security gate PASSED or WARNING
        1 - Security gate FAILED
        2 - Error during execution
    """
    exit_code = 0
    
    try:
        # Auto-detect CI mode
        if is_ci_environment() and not ci_mode:
            ci_mode = True
            
        # Setup output directory
        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Print header
        if ci_mode:
            print_ci_log("DevSecOps Security Audit - CI Mode", "group_start")
            print_ci_log(f"Target: {target}")
            print_ci_log(f"Output: {output}")
            
            ci_info = get_ci_info()
            print_ci_log(f"CI Platform: {ci_info['ci_platform']}")
            if ci_info['commit_sha']:
                print_ci_log(f"Commit: {ci_info['commit_sha'][:8]}")
            if ci_info['branch']:
                print_ci_log(f"Branch: {ci_info['branch']}")
        else:
            print("=" * 60)
            print("  DevSecOps Security Audit")
            print("=" * 60)
            print(f"  Target: {target}")
            print(f"  Output: {output}")
            print()
            
        # Initialize and run audit
        if ci_mode:
            print_ci_log("Running security scanners...", "group_end")
            print_ci_log("Scan Progress", "group_start")
            
        orchestrator = AuditOrchestrator(
            config_path=config,
            output_dir=str(output_path)
        )
        
        result = orchestrator.run_full_audit(target)
        
        if ci_mode:
            print_ci_log("Scan completed", "group_end")
            
        # Generate summary for CI consumption
        summary = {
            "audit_id": result.audit_id,
            "timestamp": result.audit_timestamp.isoformat(),
            "target": str(target),
            "gate_decision": result.gate_decision.value,
            "gate_reason": result.gate_reason,
            "total_score": result.total_score,
            "findings": {
                "total": result.total_vulnerability_count,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "scanners": [r.scanner_name for r in result.scan_results],
            "ci_info": get_ci_info() if ci_mode else None,
        }
        
        # Write summary JSON
        summary_path = output_summary or str(output_path / "audit_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
            
        # Save full reports
        saved_files = orchestrator.save_report(result, list(format))
        
        # Print results
        if ci_mode:
            print_ci_log("Results", "group_start")
            print_ci_log(f"Gate Decision: {result.gate_decision.value}")
            print_ci_log(f"Critical: {result.critical_count}")
            print_ci_log(f"High: {result.high_count}")
            print_ci_log(f"Medium: {result.medium_count}")
            print_ci_log(f"Low: {result.low_count}")
            print_ci_log(f"Total Score: {result.total_score}")
            print_ci_log("", "group_end")
            
            # CI-specific annotations
            if result.gate_decision == GateDecision.FAILED:
                print_ci_log(f"Security gate failed: {result.gate_reason}", "error")
            elif result.gate_decision == GateDecision.WARNING:
                print_ci_log(f"Security warning: {result.gate_reason}", "warning")
                
        else:
            print()
            print(result.print_summary())
            print()
            print("Reports saved:")
            for fmt, path in saved_files.items():
                print(f"  - {fmt}: {path}")
                
        # Determine exit code
        if result.gate_decision == GateDecision.FAILED:
            exit_code = 1
        elif result.gate_decision == GateDecision.WARNING and fail_on_warning:
            exit_code = 1
        elif result.gate_decision == GateDecision.ERROR:
            exit_code = 2
        else:
            exit_code = 0
            
    except Exception as e:
        print_ci_log(f"Audit failed with error: {str(e)}", "error")
        exit_code = 2
        
    # Final status
    if ci_mode:
        if exit_code == 0:
            print_ci_log("✅ Security gate PASSED")
        elif exit_code == 1:
            print_ci_log("❌ Security gate FAILED")
        else:
            print_ci_log("🚫 Security audit ERROR")
            
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
