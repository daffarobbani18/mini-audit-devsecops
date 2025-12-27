"""
Severity Calculator
===================

Calculates risk scores and determines gate decisions
based on vulnerability findings and configured thresholds.
"""

from typing import List, Tuple

from src.config import SeverityThresholds
from src.models.audit_result import GateDecision, Severity, Vulnerability


class SeverityCalculator:
    """
    Calculates severity scores and makes gate decisions.
    
    Uses configurable thresholds to determine whether
    findings should block deployment.
    
    Example:
        calculator = SeverityCalculator(thresholds)
        score = calculator.calculate_total_score(vulnerabilities)
        decision, reason = calculator.get_gate_decision(vulnerabilities)
    """
    
    def __init__(self, thresholds: SeverityThresholds):
        """
        Initialize calculator with thresholds.
        
        Args:
            thresholds: SeverityThresholds configuration
        """
        self.thresholds = thresholds
    
    def calculate_total_score(self, vulnerabilities: List[Vulnerability]) -> int:
        """
        Calculate total severity score for all vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities to score
            
        Returns:
            Total severity score
        """
        total = 0
        
        for vuln in vulnerabilities:
            score = self._get_severity_score(vuln.severity)
            total += score
        
        return total
    
    def _get_severity_score(self, severity: Severity) -> int:
        """Get score for a severity level."""
        scores = {
            Severity.CRITICAL: self.thresholds.critical_score,
            Severity.HIGH: self.thresholds.high_score,
            Severity.MEDIUM: self.thresholds.medium_score,
            Severity.LOW: self.thresholds.low_score,
            Severity.INFO: self.thresholds.info_score,
        }
        return scores.get(severity, 0)
    
    def count_by_severity(
        self, 
        vulnerabilities: List[Vulnerability]
    ) -> dict:
        """
        Count vulnerabilities by severity level.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Dictionary with counts per severity
        """
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        
        for vuln in vulnerabilities:
            counts[vuln.severity] += 1
        
        return counts
    
    def get_gate_decision(
        self, 
        vulnerabilities: List[Vulnerability]
    ) -> Tuple[GateDecision, str]:
        """
        Determine gate decision based on vulnerabilities.
        
        Checks against configured thresholds to decide
        whether to pass, warn, or block.
        
        Args:
            vulnerabilities: List of vulnerabilities to evaluate
            
        Returns:
            Tuple of (GateDecision, reason_string)
        """
        if not vulnerabilities:
            return GateDecision.PASSED, "No security vulnerabilities found"
        
        counts = self.count_by_severity(vulnerabilities)
        total_score = self.calculate_total_score(vulnerabilities)
        
        # Check for critical vulnerabilities
        if self.thresholds.block_on_critical and counts[Severity.CRITICAL] > 0:
            return (
                GateDecision.FAILED,
                f"CRITICAL vulnerabilities found: {counts[Severity.CRITICAL]}. "
                f"Critical issues must be fixed before deployment."
            )
        
        # Check high vulnerability count
        if counts[Severity.HIGH] >= self.thresholds.block_on_high_count:
            return (
                GateDecision.FAILED,
                f"Too many HIGH severity vulnerabilities: {counts[Severity.HIGH]} "
                f"(threshold: {self.thresholds.block_on_high_count})"
            )
        
        # Check medium vulnerability count
        if counts[Severity.MEDIUM] >= self.thresholds.block_on_medium_count:
            return (
                GateDecision.FAILED,
                f"Too many MEDIUM severity vulnerabilities: {counts[Severity.MEDIUM]} "
                f"(threshold: {self.thresholds.block_on_medium_count})"
            )
        
        # Check total score
        if total_score > self.thresholds.max_total_score:
            return (
                GateDecision.FAILED,
                f"Total severity score {total_score} exceeds threshold "
                f"({self.thresholds.max_total_score})"
            )
        
        # Check if there are any high findings (warning)
        if counts[Severity.HIGH] > 0:
            return (
                GateDecision.WARNING,
                f"HIGH severity vulnerabilities found: {counts[Severity.HIGH]}. "
                f"Review recommended before deployment."
            )
        
        # Check if there are medium findings (warning)
        if counts[Severity.MEDIUM] > 0:
            return (
                GateDecision.WARNING,
                f"MEDIUM severity vulnerabilities found: {counts[Severity.MEDIUM]}. "
                f"Consider reviewing before deployment."
            )
        
        # Only low/info findings
        return (
            GateDecision.PASSED,
            f"Security scan completed. Found {len(vulnerabilities)} low-risk issues."
        )
    
    def get_risk_summary(
        self, 
        vulnerabilities: List[Vulnerability]
    ) -> dict:
        """
        Generate a risk summary for reporting.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Dictionary with risk metrics
        """
        counts = self.count_by_severity(vulnerabilities)
        total_score = self.calculate_total_score(vulnerabilities)
        decision, reason = self.get_gate_decision(vulnerabilities)
        
        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": {
                "critical": counts[Severity.CRITICAL],
                "high": counts[Severity.HIGH],
                "medium": counts[Severity.MEDIUM],
                "low": counts[Severity.LOW],
                "info": counts[Severity.INFO],
            },
            "total_score": total_score,
            "max_score_threshold": self.thresholds.max_total_score,
            "score_percentage": round(
                (total_score / self.thresholds.max_total_score) * 100, 2
            ) if self.thresholds.max_total_score > 0 else 0,
            "gate_decision": decision.value,
            "gate_reason": reason,
        }
