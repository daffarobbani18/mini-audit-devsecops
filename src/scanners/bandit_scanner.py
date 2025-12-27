"""
Bandit Scanner Implementation
=============================

SAST (Static Application Security Testing) scanner using Bandit.
Analyzes Python source code for common security issues.

Bandit checks for:
- Hardcoded passwords and secrets
- SQL injection vulnerabilities
- Command injection (shell=True)
- Insecure use of pickle/yaml
- Weak cryptographic functions
- And many more...

Reference: https://bandit.readthedocs.io/
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config import BanditConfig, GateConfig
from src.models.audit_result import ScanResult, Severity, Vulnerability
from src.models.compliance import get_cwe_from_bandit_test, get_compliance_mapping
from src.scanners.base_scanner import BaseScanner


class BanditScanner(BaseScanner):
    """
    Bandit SAST scanner for Python code.
    
    Wraps the Bandit security linter to provide structured
    vulnerability results with compliance mappings.
    
    Example:
        scanner = BanditScanner()
        result = scanner.scan("./src")
        
        for vuln in result.vulnerabilities:
            print(f"{vuln.severity}: {vuln.title}")
    """

    def __init__(self, config: Optional[GateConfig] = None):
        """Initialize Bandit scanner."""
        super().__init__(config)
        self.bandit_config: BanditConfig = self.config.bandit if config else BanditConfig()

    @property
    def name(self) -> str:
        """Scanner name identifier."""
        return "bandit"

    def _get_bandit_executable(self) -> str:
        """Get the path to bandit executable."""
        import sys
        import shutil
        from pathlib import Path

        # First try to find bandit in the same directory as Python
        python_dir = Path(sys.executable).parent
        bandit_path = python_dir / "bandit.exe" if sys.platform == "win32" else python_dir / "bandit"

        if bandit_path.exists():
            return str(bandit_path)

        # Fall back to shutil.which
        found = shutil.which("bandit")
        if found:
            return found

        return "bandit"

    @property
    def version(self) -> str:
        """Get installed Bandit version."""
        try:
            result = subprocess.run(
                [self._get_bandit_executable(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Parse version from output
                return result.stdout.strip().split()[-1]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return "unknown"

    def is_available(self) -> bool:
        """Check if Bandit is installed and available."""
        try:
            result = subprocess.run(
                [self._get_bandit_executable(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def scan(self, target_path: str) -> ScanResult:
        """
        Run Bandit scan on target path.
        
        Args:
            target_path: Path to Python file or directory
            
        Returns:
            ScanResult with vulnerabilities found
        """
        start_time = datetime.now()

        # Validate target exists
        target = Path(target_path)
        if not target.exists():
            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                success=False,
                error_message=f"Target path does not exist: {target_path}",
            )

        # Check if Bandit is available
        if not self.is_available():
            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                success=False,
                error_message="Bandit is not installed. Run: pip install bandit",
            )

        try:
            # Build Bandit command
            cmd = self._build_command(target_path)

            # Execute Bandit
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            # Parse JSON output
            raw_output = self._parse_output(result.stdout)

            # Convert to vulnerabilities
            vulnerabilities = self._convert_results(raw_output, target_path)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                vulnerabilities=vulnerabilities,
                scan_duration=duration,
                success=True,
                raw_output=raw_output,
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                success=False,
                error_message="Bandit scan timed out after 5 minutes",
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                success=False,
                error_message=f"Bandit scan failed: {str(e)}",
            )

    def _build_command(self, target_path: str) -> List[str]:
        """Build Bandit command with configured options."""
        cmd = [
            self._get_bandit_executable(),
            "-r",  # Recursive
            "-f", "json",  # JSON output format
            "-q",  # Quiet (no progress)
        ]

        # Add severity filter
        if self.bandit_config.severity_levels:
            severity_map = {"LOW": "l", "MEDIUM": "m", "HIGH": "h"}
            levels = "".join(
                severity_map.get(s, "")
                for s in self.bandit_config.severity_levels
            )
            # Bandit severity: -l (low and above), -ll (medium and above), -lll (high only)
            # For now, we include all levels if LOW is included

        # Add confidence filter
        if self.bandit_config.confidence_levels:
            conf_map = {"LOW": "l", "MEDIUM": "m", "HIGH": "h"}
            # Similar logic for confidence

        # Add exclude directories
        if self.bandit_config.exclude_dirs:
            exclude = ",".join(self.bandit_config.exclude_dirs)
            cmd.extend(["--exclude", exclude])

        # Add skipped tests
        if self.bandit_config.skip_tests:
            skips = ",".join(self.bandit_config.skip_tests)
            cmd.extend(["--skip", skips])

        # Add baseline if configured
        if self.bandit_config.baseline_file:
            baseline = Path(self.bandit_config.baseline_file)
            if baseline.exists():
                cmd.extend(["--baseline", str(baseline)])

        # Add target path
        cmd.append(target_path)

        return cmd

    def _parse_output(self, stdout: str) -> Dict[str, Any]:
        """Parse Bandit JSON output."""
        if not stdout.strip():
            return {"results": [], "metrics": {}}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"results": [], "metrics": {}, "parse_error": stdout}

    def _convert_results(
        self,
        raw_output: Dict[str, Any],
        target_path: str
    ) -> List[Vulnerability]:
        """Convert Bandit results to Vulnerability objects."""
        vulnerabilities = []

        results = raw_output.get("results", [])

        for idx, finding in enumerate(results):
            vuln = self._convert_finding(finding, idx)
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _convert_finding(self, finding: Dict[str, Any], index: int) -> Vulnerability:
        """Convert a single Bandit finding to Vulnerability."""
        test_id = finding.get("test_id", "B000")
        severity_str = finding.get("issue_severity", "MEDIUM")

        # Get CWE mapping
        cwe_id = get_cwe_from_bandit_test(test_id)
        owasp_id = None

        # Get compliance mapping if CWE exists
        if cwe_id:
            compliance = get_compliance_mapping(cwe_id)
            if compliance:
                owasp_id = compliance.owasp_category

        # Build remediation advice
        remediation = self._get_remediation(test_id, finding)

        return Vulnerability(
            id=f"BANDIT-{test_id}-{index:04d}",
            title=finding.get("issue_text", "Unknown Issue"),
            description=finding.get("issue_text", ""),
            severity=Severity.from_string(severity_str),
            confidence=finding.get("issue_confidence", "MEDIUM"),
            scanner="bandit",
            file_path=finding.get("filename"),
            line_number=finding.get("line_number"),
            column_number=finding.get("col_offset"),
            code_snippet=finding.get("code", ""),
            test_id=test_id,
            cwe_id=cwe_id,
            owasp_id=owasp_id,
            remediation=remediation,
            references=[
                f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html",
            ],
            metadata={
                "test_name": finding.get("test_name"),
                "line_range": finding.get("line_range", []),
                "more_info": finding.get("more_info"),
            },
        )

    def _get_remediation(self, test_id: str, finding: Dict[str, Any]) -> str:
        """Get remediation advice for a finding."""
        # Common remediation advice based on test ID
        remediations = {
            "B101": "Remove assert statements from production code. Use proper error handling instead.",
            "B102": "Avoid using exec(). If dynamic code execution is required, consider safer alternatives.",
            "B103": "Set secure file permissions (e.g., 0o600 for sensitive files).",
            "B104": "Avoid binding to all interfaces (0.0.0.0). Bind to specific interfaces instead.",
            "B105": "Remove hardcoded passwords. Use environment variables or secure secret management.",
            "B106": "Remove hardcoded password arguments. Use secure secret management.",
            "B107": "Remove hardcoded default passwords. Require passwords to be set explicitly.",
            "B108": "Use tempfile module instead of hardcoded /tmp paths.",
            "B301": "Avoid pickle for untrusted data. Use JSON or other safe serialization formats.",
            "B302": "Avoid marshal for untrusted data. Use JSON or other safe serialization formats.",
            "B303": "Use SHA-256 or stronger hash algorithms. MD5/SHA-1 are cryptographically weak.",
            "B307": "Avoid eval(). If parsing is needed, use ast.literal_eval() for literals.",
            "B311": "Use secrets module instead of random for security-sensitive operations.",
            "B501": "Enable certificate verification: verify=True in requests.",
            "B502": "Use TLS 1.2 or higher. Avoid SSLv2/SSLv3/TLS 1.0.",
            "B506": "Use yaml.safe_load() instead of yaml.load().",
            "B602": "Avoid shell=True in subprocess. Use shell=False with list of arguments.",
            "B608": "Use parameterized queries to prevent SQL injection.",
        }

        return remediations.get(test_id, finding.get("more_info", "Review and fix the security issue."))
