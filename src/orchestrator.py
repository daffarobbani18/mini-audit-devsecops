"""
Audit Orchestrator
==================

High-level orchestration of security audits with
support for multiple scan modes and report generation.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.config import Config, load_config
from src.gate.security_gate import SecurityGate
from src.models.audit_result import AuditResult


class AuditOrchestrator:
    """
    High-level orchestrator for security audits.
    
    Provides a simplified interface for running audits,
    generating reports, and managing audit history.
    
    Example:
        orchestrator = AuditOrchestrator()
        result = orchestrator.run_full_audit("./my_project")
        orchestrator.save_report(result)
    """
    
    def __init__(
        self, 
        config_path: Optional[str] = None,
        output_dir: str = "reports"
    ):
        """
        Initialize orchestrator.
        
        Args:
            config_path: Path to configuration file
            output_dir: Directory for saving reports
        """
        self.config = load_config(config_path)
        self.gate = SecurityGate(config=self.config)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def run_full_audit(
        self, 
        target_path: str,
        audit_id: Optional[str] = None
    ) -> AuditResult:
        """
        Run a complete security audit.
        
        Args:
            target_path: Path to scan
            audit_id: Optional custom audit ID
            
        Returns:
            AuditResult with all findings
        """
        return self.gate.run_audit(target_path, audit_id)
    
    def save_report(
        self, 
        result: AuditResult,
        formats: Optional[list] = None
    ) -> dict:
        """
        Save audit report to files.
        
        Args:
            result: AuditResult to save
            formats: List of formats ["json", "html"]
            
        Returns:
            Dictionary with file paths of saved reports
        """
        formats = formats or self.config.gate.report.formats
        saved_files = {}
        
        timestamp = result.audit_timestamp.strftime("%Y%m%d_%H%M%S")
        base_name = f"audit_report_{timestamp}"
        
        if "json" in formats:
            json_path = self.output_dir / f"{base_name}.json"
            self._save_json_report(result, json_path)
            saved_files["json"] = str(json_path)
        
        if "html" in formats:
            html_path = self.output_dir / f"{base_name}.html"
            self._save_html_report(result, html_path)
            saved_files["html"] = str(html_path)
        
        return saved_files
    
    def _save_json_report(self, result: AuditResult, path: Path) -> None:
        """Save report as JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
    
    def _save_html_report(self, result: AuditResult, path: Path) -> None:
        """Save report as HTML."""
        html_content = self._generate_html_report(result)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
    
    def _generate_html_report(self, result: AuditResult) -> str:
        """Generate HTML report content."""
        # Simple HTML template
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "INFO": "#17a2b8",
        }
        
        vulnerabilities_html = ""
        for vuln in result.all_vulnerabilities:
            color = severity_colors.get(vuln.severity.value, "#6c757d")
            vulnerabilities_html += f"""
            <tr>
                <td><span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 4px;">{vuln.severity.value}</span></td>
                <td>{vuln.title}</td>
                <td>{vuln.file_path or 'N/A'}:{vuln.line_number or 'N/A'}</td>
                <td>{vuln.scanner}</td>
                <td>{vuln.cwe_id or 'N/A'}</td>
            </tr>
            """
        
        gate_color = "#28a745" if result.passed else "#dc3545"
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {result.audit_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .summary-card h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #666; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; }}
        .gate-status {{ background: {gate_color}; color: white; padding: 15px 30px; border-radius: 8px; display: inline-block; font-size: 18px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .meta {{ color: #666; font-size: 14px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Audit Report</h1>
        
        <div class="meta">
            <strong>Audit ID:</strong> {result.audit_id} |
            <strong>Date:</strong> {result.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')} |
            <strong>Target:</strong> {result.target_path}
        </div>
        
        <div class="gate-status">{result.gate_decision.emoji} {result.gate_decision.value}</div>
        <p><strong>Reason:</strong> {result.gate_reason}</p>
        
        <h2>📊 Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>🔴 Critical</h3>
                <div class="value" style="color: #dc3545;">{result.critical_count}</div>
            </div>
            <div class="summary-card">
                <h3>🟠 High</h3>
                <div class="value" style="color: #fd7e14;">{result.high_count}</div>
            </div>
            <div class="summary-card">
                <h3>🟡 Medium</h3>
                <div class="value" style="color: #ffc107;">{result.medium_count}</div>
            </div>
            <div class="summary-card">
                <h3>🟢 Low</h3>
                <div class="value" style="color: #28a745;">{result.low_count}</div>
            </div>
            <div class="summary-card">
                <h3>📊 Total Score</h3>
                <div class="value">{result.total_score}</div>
            </div>
        </div>
        
        <h2>🔍 Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Location</th>
                    <th>Scanner</th>
                    <th>CWE</th>
                </tr>
            </thead>
            <tbody>
                {vulnerabilities_html if vulnerabilities_html else '<tr><td colspan="5" style="text-align: center; color: #28a745;">✅ No vulnerabilities found!</td></tr>'}
            </tbody>
        </table>
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px;">
            Generated by DevSecOps Gate | Mini Audit Tools 2025
        </footer>
    </div>
</body>
</html>
        """
        
        return html
    
    def print_summary(self, result: AuditResult) -> None:
        """Print audit summary to console."""
        print(result.print_summary())
