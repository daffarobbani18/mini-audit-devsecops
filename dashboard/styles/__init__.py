"""
Dashboard Styles Package
========================

Centralized styling for the DevSecOps Dashboard.
"""

from .theme import (
    COLORS,
    SEVERITY_COLORS,
    GATE_COLORS,
    FONTS,
    SPACING,
    RADIUS,
    SHADOWS,
    get_custom_css,
    severity_badge,
    status_banner,
    card,
    gradient_card,
)

__all__ = [
    'COLORS',
    'SEVERITY_COLORS',
    'GATE_COLORS',
    'FONTS',
    'SPACING',
    'RADIUS',
    'SHADOWS',
    'get_custom_css',
    'severity_badge',
    'status_banner',
    'card',
    'gradient_card',
]
