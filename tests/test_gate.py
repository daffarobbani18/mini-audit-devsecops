"""
Test Gate Logic
===============

Unit tests for security gate decision logic.
"""

import pytest
from pathlib import Path
from datetime import datetime

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import SeverityThresholds
from src.gate.severity_calculator import SeverityCalculator
from src.models.audit_result import Severity, Vulnerability, GateDecision


class TestSeverityCalculator:
    """Tests for SeverityCalculator."""
    
    @pytest.fixture
    def default_thresholds(self):
        """Default severity thresholds."""
        return SeverityThresholds()
    
    @pytest.fixture
    def calculator(self, default_thresholds):
        """Create calculator with default thresholds."""
        return SeverityCalculator(default_thresholds)
    
    def create_vuln(self, severity: Severity) -> Vulnerability:
        """Helper to create a vulnerability with given severity."""
        return Vulnerability(
            id=f"TEST-{severity.value}",
            title=f"Test {severity.value} vulnerability",
            description="Test description",
            severity=severity,
            scanner="test",
        )
    
    def test_calculate_total_score_empty(self, calculator):
        """Test score calculation with no vulnerabilities."""
        score = calculator.calculate_total_score([])
        assert score == 0
    
    def test_calculate_total_score_single(self, calculator):
        """Test score calculation with single vulnerability."""
        vulns = [self.create_vuln(Severity.CRITICAL)]
        score = calculator.calculate_total_score(vulns)
        assert score == 10  # Default CRITICAL score
    
    def test_calculate_total_score_mixed(self, calculator):
        """Test score calculation with mixed severities."""
        vulns = [
            self.create_vuln(Severity.CRITICAL),  # 10
            self.create_vuln(Severity.HIGH),       # 8
            self.create_vuln(Severity.MEDIUM),     # 5
            self.create_vuln(Severity.LOW),        # 2
        ]
        score = calculator.calculate_total_score(vulns)
        assert score == 25  # 10 + 8 + 5 + 2
    
    def test_count_by_severity(self, calculator):
        """Test counting vulnerabilities by severity."""
        vulns = [
            self.create_vuln(Severity.CRITICAL),
            self.create_vuln(Severity.CRITICAL),
            self.create_vuln(Severity.HIGH),
            self.create_vuln(Severity.MEDIUM),
            self.create_vuln(Severity.LOW),
            self.create_vuln(Severity.LOW),
            self.create_vuln(Severity.LOW),
        ]
        
        counts = calculator.count_by_severity(vulns)
        
        assert counts[Severity.CRITICAL] == 2
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.MEDIUM] == 1
        assert counts[Severity.LOW] == 3
        assert counts[Severity.INFO] == 0
    
    def test_gate_decision_no_vulns(self, calculator):
        """Test gate decision with no vulnerabilities."""
        decision, reason = calculator.get_gate_decision([])
        
        assert decision == GateDecision.PASSED
        assert "No security vulnerabilities" in reason
    
    def test_gate_decision_critical_blocks(self, calculator):
        """Test that critical vulnerabilities block deployment."""
        vulns = [self.create_vuln(Severity.CRITICAL)]
        
        decision, reason = calculator.get_gate_decision(vulns)
        
        assert decision == GateDecision.FAILED
        assert "CRITICAL" in reason
    
    def test_gate_decision_high_count_blocks(self, calculator):
        """Test that too many HIGH vulnerabilities block deployment."""
        # Default threshold is 3
        vulns = [
            self.create_vuln(Severity.HIGH),
            self.create_vuln(Severity.HIGH),
            self.create_vuln(Severity.HIGH),
        ]
        
        decision, reason = calculator.get_gate_decision(vulns)
        
        assert decision == GateDecision.FAILED
        assert "HIGH" in reason
    
    def test_gate_decision_high_warning(self, calculator):
        """Test that some HIGH vulnerabilities trigger warning."""
        vulns = [
            self.create_vuln(Severity.HIGH),
            self.create_vuln(Severity.HIGH),
        ]
        
        decision, reason = calculator.get_gate_decision(vulns)
        
        assert decision == GateDecision.WARNING
        assert "HIGH" in reason
    
    def test_gate_decision_score_threshold(self):
        """Test that exceeding score threshold blocks deployment."""
        thresholds = SeverityThresholds(
            block_on_critical=False,  # Disable critical blocking
            max_total_score=10,
        )
        calculator = SeverityCalculator(thresholds)
        
        vulns = [
            self.create_vuln(Severity.HIGH),   # 8
            self.create_vuln(Severity.MEDIUM), # 5
        ]  # Total: 13
        
        decision, reason = calculator.get_gate_decision(vulns)
        
        assert decision == GateDecision.FAILED
        assert "score" in reason.lower()
    
    def test_gate_decision_only_low(self, calculator):
        """Test that only LOW findings pass."""
        vulns = [
            self.create_vuln(Severity.LOW),
            self.create_vuln(Severity.LOW),
            self.create_vuln(Severity.INFO),
        ]
        
        decision, reason = calculator.get_gate_decision(vulns)
        
        assert decision == GateDecision.PASSED


class TestGateDecision:
    """Tests for GateDecision enum."""
    
    def test_exit_codes(self):
        """Test exit codes for CI/CD integration."""
        assert GateDecision.PASSED.exit_code == 0
        assert GateDecision.WARNING.exit_code == 0
        assert GateDecision.FAILED.exit_code == 1
        assert GateDecision.ERROR.exit_code == 2
    
    def test_emojis(self):
        """Test emoji indicators."""
        assert GateDecision.PASSED.emoji == "✅"
        assert GateDecision.FAILED.emoji == "❌"
        assert GateDecision.WARNING.emoji == "⚠️"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
