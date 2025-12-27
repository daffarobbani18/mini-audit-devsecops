"""
Safety Scanner Implementation
=============================

SCA (Software Composition Analysis) scanner using Safety.
Checks Python dependencies for known security vulnerabilities.

Safety checks:
- Known CVEs in installed packages
- Outdated packages with security issues
- Packages with security advisories

Reference: https://pyup.io/safety/
"""

import json
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.config import GateConfig, SafetyConfig
from src.models.audit_result import ScanResult, Severity, Vulnerability
from src.scanners.base_scanner import BaseScanner


class SafetyScanner(BaseScanner):
    """
    Safety SCA scanner for Python dependencies.
    
    Checks requirements files or installed packages against
    the Safety vulnerability database.
    
    Example:
        scanner = SafetyScanner()
        result = scanner.scan("./requirements.txt")
        
        for vuln in result.vulnerabilities:
            print(f"{vuln.cve_id}: {vuln.title}")
    """
    
    def __init__(self, config: Optional[GateConfig] = None):
        """Initialize Safety scanner."""
        super().__init__(config)
        self.safety_config: SafetyConfig = self.config.safety if config else SafetyConfig()
    
    def _get_safety_executable(self) -> str:
        """Get the path to safety executable."""
        import sys
        import shutil
        from pathlib import Path
        
        # First try to find safety in the same directory as Python
        python_dir = Path(sys.executable).parent
        safety_path = python_dir / "safety.exe" if sys.platform == "win32" else python_dir / "safety"
        
        if safety_path.exists():
            return str(safety_path)
        
        # Fall back to shutil.which
        found = shutil.which("safety")
        if found:
            return found
        
        return "safety"
    
    @property
    def name(self) -> str:
        """Scanner name identifier."""
        return "safety"
    
    @property
    def version(self) -> str:
        """Get installed Safety version."""
        try:
            result = subprocess.run(
                [self._get_safety_executable(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip().split()[-1]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return "unknown"
    
    def is_available(self) -> bool:
        """Check if Safety is installed and available."""
        try:
            result = subprocess.run(
                [self._get_safety_executable(), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def scan(self, target_path: str) -> ScanResult:
        """
        Run Safety scan on requirements file or directory.
        
        Args:
            target_path: Path to requirements.txt or project directory
            
        Returns:
            ScanResult with vulnerabilities found
        """
        start_time = datetime.now()
        target = Path(target_path)
        
        # Find requirements files
        req_files = self._find_requirements_files(target)
        
        if not req_files:
            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                success=True,
                vulnerabilities=[],
                error_message="No requirements files found",
            )
        
        # Check if Safety is available
        if not self.is_available():
            return ScanResult(
                scanner_name=self.name,
                scan_timestamp=start_time,
                target_path=target_path,
                success=False,
                error_message="Safety is not installed. Run: pip install safety",
            )
        
        all_vulnerabilities = []
        raw_outputs = []
        errors = []
        
        for req_file in req_files:
            try:
                result = self._scan_requirements_file(req_file)
                all_vulnerabilities.extend(result.get("vulnerabilities", []))
                raw_outputs.append(result)
            except Exception as e:
                errors.append(f"Error scanning {req_file}: {str(e)}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return ScanResult(
            scanner_name=self.name,
            scan_timestamp=start_time,
            target_path=target_path,
            vulnerabilities=all_vulnerabilities,
            scan_duration=duration,
            success=len(errors) == 0,
            error_message="; ".join(errors) if errors else None,
            raw_output={"scans": raw_outputs, "files_scanned": [str(f) for f in req_files]},
        )
    
    def _find_requirements_files(self, target: Path) -> List[Path]:
        """Find requirements files in target path."""
        if target.is_file():
            return [target]
        
        if target.is_dir():
            req_files = []
            for pattern in self.safety_config.requirements_files:
                req_files.extend(target.glob(pattern))
                req_files.extend(target.glob(f"**/{pattern}"))
            return list(set(req_files))
        
        return []
    
    def _scan_requirements_file(self, req_file: Path) -> Dict[str, Any]:
        """Scan a single requirements file."""
        cmd = [
            self._get_safety_executable(), "check",
            "-r", str(req_file),
            "--json",
        ]
        
        # Add ignored vulnerabilities
        for vuln_id in self.safety_config.ignore_vulns:
            cmd.extend(["--ignore", vuln_id])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            # Parse output (Safety returns exit code 255 if vulnerabilities found)
            output = result.stdout or result.stderr
            parsed = self._parse_output(output)
            
            # Convert to vulnerabilities
            vulnerabilities = self._convert_results(parsed, req_file)
            
            return {
                "file": str(req_file),
                "raw": parsed,
                "vulnerabilities": vulnerabilities,
            }
            
        except subprocess.TimeoutExpired:
            raise Exception("Safety scan timed out")
        except Exception as e:
            raise Exception(f"Safety scan failed: {str(e)}")
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Safety JSON output."""
        if not output.strip():
            return {"vulnerabilities": []}
        
        try:
            # Safety 2.x returns a report object
            data = json.loads(output)
            
            # Handle different Safety output formats
            if isinstance(data, dict):
                return data
            elif isinstance(data, list):
                # Older Safety format
                return {"vulnerabilities": data}
            
        except json.JSONDecodeError:
            # Try to extract JSON from output
            lines = output.strip().split("\n")
            for line in lines:
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        
        return {"vulnerabilities": [], "parse_error": output}
    
    def _convert_results(
        self, 
        parsed: Dict[str, Any],
        req_file: Path
    ) -> List[Vulnerability]:
        """Convert Safety results to Vulnerability objects."""
        vulnerabilities = []
        
        # Handle Safety 3.x format
        if "report_meta" in parsed:
            vulns = parsed.get("affected_packages", {})
            for pkg_name, pkg_data in vulns.items():
                for vuln_info in pkg_data.get("vulns", []):
                    vuln = self._convert_v3_finding(pkg_name, pkg_data, vuln_info, req_file)
                    vulnerabilities.append(vuln)
        
        # Handle Safety 2.x format
        elif "vulnerabilities" in parsed:
            for idx, vuln_data in enumerate(parsed["vulnerabilities"]):
                vuln = self._convert_v2_finding(vuln_data, idx, req_file)
                vulnerabilities.append(vuln)
        
        # Handle legacy list format
        elif isinstance(parsed.get("scanned_packages"), list):
            # Process scan results
            pass
        
        return vulnerabilities
    
    def _convert_v3_finding(
        self,
        pkg_name: str,
        pkg_data: Dict,
        vuln_info: Dict,
        req_file: Path
    ) -> Vulnerability:
        """Convert Safety 3.x finding to Vulnerability."""
        vuln_id = vuln_info.get("id", "UNKNOWN")
        severity_str = vuln_info.get("severity", {}).get("source", "MEDIUM")
        
        # Normalize severity
        severity = self._normalize_severity(severity_str)
        
        return Vulnerability(
            id=f"SAFETY-{vuln_id}",
            title=f"Vulnerable dependency: {pkg_name}",
            description=vuln_info.get("advisory", "No description available"),
            severity=severity,
            confidence="HIGH",
            scanner="safety",
            file_path=str(req_file),
            cve_id=vuln_info.get("cve"),
            remediation=self._get_remediation(pkg_name, pkg_data, vuln_info),
            references=vuln_info.get("references", []),
            metadata={
                "package": pkg_name,
                "installed_version": pkg_data.get("version"),
                "vulnerable_versions": vuln_info.get("vulnerable_versions"),
                "patched_versions": vuln_info.get("patched_versions"),
            },
        )
    
    def _convert_v2_finding(
        self,
        vuln_data: Any,
        index: int,
        req_file: Path
    ) -> Vulnerability:
        """Convert Safety 2.x finding to Vulnerability."""
        # Safety 2.x returns [package, affected, installed, description, id]
        if isinstance(vuln_data, list) and len(vuln_data) >= 5:
            pkg_name = vuln_data[0]
            affected = vuln_data[1]
            installed = vuln_data[2]
            description = vuln_data[3]
            vuln_id = vuln_data[4]
        elif isinstance(vuln_data, dict):
            pkg_name = vuln_data.get("package_name", "unknown")
            affected = vuln_data.get("vulnerable_versions", "")
            installed = vuln_data.get("analyzed_version", "")
            description = vuln_data.get("advisory", "")
            vuln_id = vuln_data.get("vulnerability_id", f"SAFETY-{index}")
        else:
            # Fallback
            return Vulnerability(
                id=f"SAFETY-UNKNOWN-{index}",
                title="Unknown vulnerability",
                description=str(vuln_data),
                severity=Severity.MEDIUM,
                scanner="safety",
                file_path=str(req_file),
            )
        
        # Estimate severity based on keywords
        severity = self._estimate_severity(description)
        
        return Vulnerability(
            id=f"SAFETY-{vuln_id}",
            title=f"Vulnerable dependency: {pkg_name}",
            description=description,
            severity=severity,
            confidence="HIGH",
            scanner="safety",
            file_path=str(req_file),
            remediation=f"Update {pkg_name} to a patched version. Vulnerable: {affected}, Installed: {installed}",
            metadata={
                "package": pkg_name,
                "installed_version": installed,
                "vulnerable_versions": affected,
            },
        )
    
    def _normalize_severity(self, severity_str: str) -> Severity:
        """Normalize severity string to Severity enum."""
        severity_upper = severity_str.upper()
        
        # Map various severity names
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFORMATIONAL": Severity.INFO,
            "INFO": Severity.INFO,
            "NONE": Severity.INFO,
        }
        
        return mapping.get(severity_upper, Severity.MEDIUM)
    
    def _estimate_severity(self, description: str) -> Severity:
        """Estimate severity based on vulnerability description."""
        desc_lower = description.lower()
        
        # Critical indicators
        if any(word in desc_lower for word in [
            "remote code execution", "rce", "critical",
            "authentication bypass", "privilege escalation"
        ]):
            return Severity.CRITICAL
        
        # High indicators
        if any(word in desc_lower for word in [
            "sql injection", "command injection", "xss",
            "path traversal", "directory traversal", "high"
        ]):
            return Severity.HIGH
        
        # Low indicators
        if any(word in desc_lower for word in [
            "dos", "denial of service", "low", "minor"
        ]):
            return Severity.LOW
        
        # Default to medium
        return Severity.MEDIUM
    
    def _get_remediation(
        self, 
        pkg_name: str, 
        pkg_data: Dict, 
        vuln_info: Dict
    ) -> str:
        """Generate remediation advice."""
        patched = vuln_info.get("patched_versions", [])
        installed = pkg_data.get("version", "unknown")
        
        if patched:
            patched_str = ", ".join(patched) if isinstance(patched, list) else patched
            return f"Update {pkg_name} from {installed} to {patched_str}"
        
        return f"Update {pkg_name} to the latest secure version. Current: {installed}"
