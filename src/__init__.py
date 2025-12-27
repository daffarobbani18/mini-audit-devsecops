"""
DevSecOps Gate - Core Module
============================

Automated Security Audit for CI/CD Pipeline.
This module provides security scanning and gate decision capabilities.

Modules:
    - config: Configuration management
    - scanners: Security scanning tools (Bandit, Safety)
    - reporters: Report generation (JSON, HTML, PDF)
    - gate: Security gate decision logic
    - models: Data models for audit results

Usage:
    from src import SecurityGate, AuditOrchestrator
    
    gate = SecurityGate(config_path="gate_config.yaml")
    result = gate.run_audit(target_path="./your_project")
    
    if result.passed:
        print("✅ Security gate passed!")
    else:
        print("❌ Security gate failed!")
        print(result.summary)

Author: DevSecOps Audit Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "DevSecOps Audit Team"

# Core exports
from src.config import Config, GateConfig
from src.gate.security_gate import SecurityGate
from src.orchestrator import AuditOrchestrator

__all__ = [
    "Config",
    "GateConfig",
    "SecurityGate",
    "AuditOrchestrator",
    "__version__",
]
