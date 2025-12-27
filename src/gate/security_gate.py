"""
Security Gate
=============

Main entry point for security gate decisions.
Orchestrates scanners and evaluates results against thresholds.
"""

import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from src.config import Config, load_config
from src.gate.severity_calculator import SeverityCalculator
from src.models.audit_result import AuditResult, GateDecision, ScanResult
from src.scanners import BanditScanner, SafetyScanner


class SecurityGate:
    """
    Security Gate for CI/CD pipelines.
    
    Coordinates security scans and determines whether code
    should be allowed to proceed through the pipeline.
    
    Example:
        gate = SecurityGate()
        result = gate.run_audit("./src")
        
        if result.passed:
            print("✅ Deployment approved")
        else:
            print("❌ Deployment blocked")
            sys.exit(1)
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        config_path: Optional[str] = None
    ):
        """
        Initialize Security Gate.
        
        Args:
            config: Config instance (takes precedence)
            config_path: Path to configuration file
        """
        if config:
            self.config = config
        elif config_path:
            self.config = load_config(config_path)
        else:
            self.config = load_config()

        self.gate_config = self.config.gate
        self.calculator = SeverityCalculator(self.gate_config.thresholds)

        # Initialize scanners
        self.scanners = self._initialize_scanners()

    def _initialize_scanners(self) -> List:
        """Initialize enabled scanners."""
        scanners = []

        if self.gate_config.bandit.enabled:
            scanners.append(BanditScanner(self.gate_config))

        if self.gate_config.safety.enabled:
            scanners.append(SafetyScanner(self.gate_config))

        return scanners

    def run_audit(
        self,
        target_path: str,
        audit_id: Optional[str] = None
    ) -> AuditResult:
        """
        Run security audit on target path.
        
        Executes all enabled scanners and aggregates results.
        
        Args:
            target_path: Path to scan (file or directory)
            audit_id: Optional custom audit ID
            
        Returns:
            AuditResult with all findings and gate decision
        """
        audit_id = audit_id or f"AUDIT-{uuid.uuid4().hex[:8].upper()}"
        audit_timestamp = datetime.now()

        target = Path(target_path)
        if not target.exists():
            return AuditResult(
                audit_id=audit_id,
                audit_timestamp=audit_timestamp,
                target_path=target_path,
                gate_decision=GateDecision.ERROR,
                gate_reason=f"Target path does not exist: {target_path}",
            )

        # Run all scanners
        scan_results: List[ScanResult] = []
        all_vulnerabilities = []

        for scanner in self.scanners:
            try:
                result = scanner.scan(str(target))
                scan_results.append(result)
                all_vulnerabilities.extend(result.vulnerabilities)

                # Check fail-fast
                if self.gate_config.fail_fast:
                    critical_found = any(
                        v.severity.value == "CRITICAL"
                        for v in result.vulnerabilities
                    )
                    if critical_found:
                        break

            except Exception as e:
                # Create error result for failed scanner
                error_result = ScanResult(
                    scanner_name=scanner.name,
                    scan_timestamp=datetime.now(),
                    target_path=str(target),
                    success=False,
                    error_message=str(e),
                )
                scan_results.append(error_result)

        # Calculate gate decision
        gate_decision, gate_reason = self.calculator.get_gate_decision(
            all_vulnerabilities
        )
        total_score = self.calculator.calculate_total_score(all_vulnerabilities)

        # Get git info if available
        git_commit, git_branch = self._get_git_info(target)

        return AuditResult(
            audit_id=audit_id,
            audit_timestamp=audit_timestamp,
            target_path=str(target.absolute()),
            scan_results=scan_results,
            gate_decision=gate_decision,
            gate_reason=gate_reason,
            total_score=total_score,
            git_commit=git_commit,
            git_branch=git_branch,
            config_used=self.config.to_dict(),
        )

    def _get_git_info(self, target: Path) -> tuple:
        """Get git commit and branch info if available."""
        try:
            import subprocess

            # Get current directory
            cwd = target if target.is_dir() else target.parent

            # Get commit hash
            commit_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=5,
            )
            commit = commit_result.stdout.strip() if commit_result.returncode == 0 else None

            # Get branch name
            branch_result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=5,
            )
            branch = branch_result.stdout.strip() if branch_result.returncode == 0 else None

            return commit, branch

        except Exception:
            return None, None

    def check_scanners(self) -> dict:
        """
        Check status of all scanners.
        
        Returns:
            Dictionary with scanner availability status
        """
        status = {}

        for scanner in self.scanners:
            status[scanner.name] = {
                "available": scanner.is_available(),
                "version": scanner.version,
            }

        return status

    def get_config_summary(self) -> dict:
        """Get summary of current gate configuration."""
        return {
            "thresholds": {
                "block_on_critical": self.gate_config.thresholds.block_on_critical,
                "block_on_high_count": self.gate_config.thresholds.block_on_high_count,
                "max_total_score": self.gate_config.thresholds.max_total_score,
            },
            "scanners": self.check_scanners(),
            "fail_fast": self.gate_config.fail_fast,
        }
