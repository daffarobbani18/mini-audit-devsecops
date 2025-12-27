"""
Configuration Management Module
===============================

Handles all configuration for the DevSecOps Gate including:
- Gate thresholds and rules
- Scanner configurations
- Report settings
- Environment-specific overrides

Supports YAML configuration files and environment variables.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class SeverityThresholds:
    """Severity thresholds for gate decisions."""

    block_on_critical: bool = True
    block_on_high_count: int = 3
    block_on_medium_count: int = 10
    max_total_score: int = 25

    # Severity scores for calculating total
    critical_score: int = 10
    high_score: int = 8
    medium_score: int = 5
    low_score: int = 2
    info_score: int = 0


@dataclass
class BanditConfig:
    """Configuration for Bandit SAST scanner."""

    enabled: bool = True
    severity_levels: List[str] = field(default_factory=lambda: ["LOW", "MEDIUM", "HIGH"])
    confidence_levels: List[str] = field(default_factory=lambda: ["LOW", "MEDIUM", "HIGH"])
    exclude_dirs: List[str] = field(default_factory=lambda: [".venv", "venv", "tests", "node_modules"])
    skip_tests: List[str] = field(default_factory=list)  # e.g., ["B101", "B102"]
    baseline_file: Optional[str] = None


@dataclass
class SafetyConfig:
    """Configuration for Safety dependency checker."""

    enabled: bool = True
    requirements_files: List[str] = field(default_factory=lambda: ["requirements.txt"])
    ignore_vulns: List[str] = field(default_factory=list)  # CVE IDs to ignore
    check_full_report: bool = True


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["json", "html"])
    include_code_snippets: bool = True
    include_remediation: bool = True
    max_issues_in_summary: int = 20


@dataclass
class GateConfig:
    """Main gate configuration combining all settings."""

    thresholds: SeverityThresholds = field(default_factory=SeverityThresholds)
    bandit: BanditConfig = field(default_factory=BanditConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    # General settings
    fail_fast: bool = False  # Stop on first critical finding
    verbose: bool = False
    quiet: bool = False


class Config:
    """
    Configuration manager for DevSecOps Gate.
    
    Loads configuration from YAML files with environment variable overrides.
    
    Example:
        config = Config.load("gate_config.yaml")
        print(config.gate.thresholds.block_on_critical)
    """

    DEFAULT_CONFIG_PATHS = [
        "gate_config.yaml",
        "gate_config.yml",
        ".devsecops-gate.yaml",
        ".devsecops-gate.yml",
    ]

    def __init__(self, gate: Optional[GateConfig] = None):
        """Initialize with optional GateConfig."""
        self.gate = gate or GateConfig()

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Config":
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to configuration file. If None, searches default locations.
            
        Returns:
            Config instance with loaded settings.
        """
        config_file = cls._find_config_file(config_path)

        if config_file and config_file.exists():
            return cls._load_from_file(config_file)

        # Return default configuration
        return cls()

    @classmethod
    def _find_config_file(cls, config_path: Optional[str]) -> Optional[Path]:
        """Find configuration file from path or default locations."""
        if config_path:
            return Path(config_path)

        for default_path in cls.DEFAULT_CONFIG_PATHS:
            path = Path(default_path)
            if path.exists():
                return path

        return None

    @classmethod
    def _load_from_file(cls, config_file: Path) -> "Config":
        """Load configuration from YAML file."""
        with open(config_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls._parse_config(data)

    @classmethod
    def _parse_config(cls, data: Dict[str, Any]) -> "Config":
        """Parse configuration dictionary into Config object."""
        gate_data = data.get("gate", {})

        # Parse thresholds
        thresholds_data = gate_data.get("thresholds", {})
        thresholds = SeverityThresholds(
            block_on_critical=thresholds_data.get("block_on_critical", True),
            block_on_high_count=thresholds_data.get("block_on_high_count", 3),
            block_on_medium_count=thresholds_data.get("block_on_medium_count", 10),
            max_total_score=thresholds_data.get("max_total_score", 25),
            critical_score=thresholds_data.get("critical_score", 10),
            high_score=thresholds_data.get("high_score", 8),
            medium_score=thresholds_data.get("medium_score", 5),
            low_score=thresholds_data.get("low_score", 2),
            info_score=thresholds_data.get("info_score", 0),
        )

        # Parse Bandit config
        bandit_data = gate_data.get("bandit", {})
        bandit = BanditConfig(
            enabled=bandit_data.get("enabled", True),
            severity_levels=bandit_data.get("severity_levels", ["LOW", "MEDIUM", "HIGH"]),
            confidence_levels=bandit_data.get("confidence_levels", ["LOW", "MEDIUM", "HIGH"]),
            exclude_dirs=bandit_data.get("exclude_dirs", [".venv", "venv", "tests"]),
            skip_tests=bandit_data.get("skip_tests", []),
            baseline_file=bandit_data.get("baseline_file"),
        )

        # Parse Safety config
        safety_data = gate_data.get("safety", {})
        safety = SafetyConfig(
            enabled=safety_data.get("enabled", True),
            requirements_files=safety_data.get("requirements_files", ["requirements.txt"]),
            ignore_vulns=safety_data.get("ignore_vulns", []),
            check_full_report=safety_data.get("check_full_report", True),
        )

        # Parse Report config
        report_data = gate_data.get("report", {})
        report = ReportConfig(
            output_dir=report_data.get("output_dir", "reports"),
            formats=report_data.get("formats", ["json", "html"]),
            include_code_snippets=report_data.get("include_code_snippets", True),
            include_remediation=report_data.get("include_remediation", True),
            max_issues_in_summary=report_data.get("max_issues_in_summary", 20),
        )

        # Create GateConfig
        gate_config = GateConfig(
            thresholds=thresholds,
            bandit=bandit,
            safety=safety,
            report=report,
            fail_fast=gate_data.get("fail_fast", False),
            verbose=gate_data.get("verbose", False),
            quiet=gate_data.get("quiet", False),
        )

        return cls(gate=gate_config)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "gate": {
                "thresholds": {
                    "block_on_critical": self.gate.thresholds.block_on_critical,
                    "block_on_high_count": self.gate.thresholds.block_on_high_count,
                    "block_on_medium_count": self.gate.thresholds.block_on_medium_count,
                    "max_total_score": self.gate.thresholds.max_total_score,
                },
                "bandit": {
                    "enabled": self.gate.bandit.enabled,
                    "exclude_dirs": self.gate.bandit.exclude_dirs,
                    "skip_tests": self.gate.bandit.skip_tests,
                },
                "safety": {
                    "enabled": self.gate.safety.enabled,
                    "requirements_files": self.gate.safety.requirements_files,
                },
                "report": {
                    "output_dir": self.gate.report.output_dir,
                    "formats": self.gate.report.formats,
                },
            }
        }

    def save(self, config_path: str) -> None:
        """Save configuration to YAML file."""
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)


# Convenience function for quick config loading
def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from file or use defaults."""
    return Config.load(config_path)
