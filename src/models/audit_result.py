"""
Audit Result Models
===================

Unified data structures for representing security scan results
across different scanning tools (Bandit, Safety, etc.)
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Vulnerability severity levels."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def score(self) -> int:
        """Return numeric score for severity."""
        scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        return scores[self]
    
    @property
    def emoji(self) -> str:
        """Return emoji indicator for severity."""
        emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵",
        }
        return emojis[self]
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        value_upper = value.upper()
        for severity in cls:
            if severity.value == value_upper:
                return severity
        return cls.INFO


class GateDecision(Enum):
    """Gate decision outcomes."""
    
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    ERROR = "ERROR"
    
    @property
    def emoji(self) -> str:
        """Return emoji for decision."""
        emojis = {
            GateDecision.PASSED: "✅",
            GateDecision.FAILED: "❌",
            GateDecision.WARNING: "⚠️",
            GateDecision.ERROR: "🚫",
        }
        return emojis[self]
    
    @property
    def exit_code(self) -> int:
        """Return exit code for CI/CD."""
        codes = {
            GateDecision.PASSED: 0,
            GateDecision.FAILED: 1,
            GateDecision.WARNING: 0,
            GateDecision.ERROR: 2,
        }
        return codes[self]


@dataclass
class Vulnerability:
    """
    Represents a single security vulnerability finding.
    
    Attributes:
        id: Unique identifier for this finding
        title: Short description of the vulnerability
        description: Detailed description
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        confidence: Confidence level of the finding
        file_path: Path to the affected file
        line_number: Line number where vulnerability was found
        code_snippet: Relevant code snippet
        scanner: Name of the scanner that found this (bandit, safety, etc.)
        test_id: Scanner-specific test identifier (e.g., B101 for Bandit)
        cwe_id: Common Weakness Enumeration ID
        owasp_id: OWASP Top 10 category
        remediation: Suggested fix or mitigation
        references: Links to documentation or CVE details
        metadata: Additional scanner-specific data
    """
    
    id: str
    title: str
    description: str
    severity: Severity
    scanner: str
    
    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    
    # Classification
    confidence: str = "MEDIUM"
    test_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    cve_id: Optional[str] = None
    
    # Remediation
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def location(self) -> str:
        """Return formatted location string."""
        if self.file_path:
            if self.line_number:
                return f"{self.file_path}:{self.line_number}"
            return self.file_path
        return "N/A"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "scanner": self.scanner,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "test_id": self.test_id,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """Create Vulnerability from dictionary."""
        data = data.copy()
        data["severity"] = Severity.from_string(data.get("severity", "INFO"))
        return cls(**data)


@dataclass
class ScanResult:
    """
    Result from a single scanner (Bandit or Safety).
    
    Attributes:
        scanner_name: Name of the scanner
        scan_timestamp: When the scan was performed
        target_path: Path that was scanned
        vulnerabilities: List of found vulnerabilities
        scan_duration: How long the scan took (seconds)
        error_message: Error message if scan failed
        raw_output: Original scanner output
    """
    
    scanner_name: str
    scan_timestamp: datetime
    target_path: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_duration: float = 0.0
    success: bool = True
    error_message: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None
    
    @property
    def vulnerability_count(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        """Count of critical severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count of high severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Count of medium severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Count of low severity vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)
    
    def get_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scanner_name": self.scanner_name,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "target_path": self.target_path,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_duration": self.scan_duration,
            "success": self.success,
            "error_message": self.error_message,
            "summary": {
                "total": self.vulnerability_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            }
        }


@dataclass
class AuditResult:
    """
    Combined result from all security scans.
    
    This is the main output structure containing results from
    all scanners, the gate decision, and summary metrics.
    """
    
    audit_id: str
    audit_timestamp: datetime
    target_path: str
    scan_results: List[ScanResult] = field(default_factory=list)
    gate_decision: GateDecision = GateDecision.PASSED
    gate_reason: str = ""
    total_score: int = 0
    
    # Metadata
    config_used: Optional[Dict[str, Any]] = None
    git_commit: Optional[str] = None
    git_branch: Optional[str] = None
    
    @property
    def all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all scanners."""
        vulns = []
        for result in self.scan_results:
            vulns.extend(result.vulnerabilities)
        return vulns
    
    @property
    def total_vulnerability_count(self) -> int:
        """Total vulnerabilities across all scans."""
        return len(self.all_vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        """Total critical vulnerabilities."""
        return sum(r.critical_count for r in self.scan_results)
    
    @property
    def high_count(self) -> int:
        """Total high vulnerabilities."""
        return sum(r.high_count for r in self.scan_results)
    
    @property
    def medium_count(self) -> int:
        """Total medium vulnerabilities."""
        return sum(r.medium_count for r in self.scan_results)
    
    @property
    def low_count(self) -> int:
        """Total low vulnerabilities."""
        return sum(r.low_count for r in self.scan_results)
    
    @property
    def passed(self) -> bool:
        """Whether the audit passed the security gate."""
        return self.gate_decision in (GateDecision.PASSED, GateDecision.WARNING)
    
    @property
    def summary(self) -> Dict[str, Any]:
        """Generate summary dictionary."""
        return {
            "audit_id": self.audit_id,
            "timestamp": self.audit_timestamp.isoformat(),
            "gate_decision": self.gate_decision.value,
            "gate_reason": self.gate_reason,
            "total_score": self.total_score,
            "findings": {
                "total": self.total_vulnerability_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "scanners": [r.scanner_name for r in self.scan_results],
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "audit_id": self.audit_id,
            "audit_timestamp": self.audit_timestamp.isoformat(),
            "target_path": self.target_path,
            "gate_decision": self.gate_decision.value,
            "gate_reason": self.gate_reason,
            "total_score": self.total_score,
            "summary": self.summary,
            "scan_results": [r.to_dict() for r in self.scan_results],
            "git_commit": self.git_commit,
            "git_branch": self.git_branch,
            "config_used": self.config_used,
        }
    
    def print_summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "",
            "=" * 60,
            f"  {self.gate_decision.emoji} SECURITY AUDIT RESULT: {self.gate_decision.value}",
            "=" * 60,
            "",
            f"  Audit ID:    {self.audit_id}",
            f"  Target:      {self.target_path}",
            f"  Timestamp:   {self.audit_timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "  Findings:",
            f"    🔴 Critical:  {self.critical_count}",
            f"    🟠 High:      {self.high_count}",
            f"    🟡 Medium:    {self.medium_count}",
            f"    🟢 Low:       {self.low_count}",
            f"    📊 Total:     {self.total_vulnerability_count}",
            "",
            f"  Total Score: {self.total_score}",
            f"  Reason:      {self.gate_reason}",
            "",
            "=" * 60,
        ]
        return "\n".join(lines)
