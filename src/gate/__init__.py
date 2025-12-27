"""
Security Gate Module
====================

Contains the gate decision logic that determines whether
code should be allowed to proceed through the CI/CD pipeline.
"""

from src.gate.security_gate import SecurityGate
from src.gate.severity_calculator import SeverityCalculator

__all__ = [
    "SecurityGate",
    "SeverityCalculator",
]
