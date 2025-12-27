"""
Filter Components
=================

Sidebar and filter components for the dashboard.
"""

import streamlit as st
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
from pathlib import Path


def render_filter_sidebar() -> dict:
    """
    Render the main filter sidebar.
    
    Returns:
        Dict with filter values
    """
    filters = {}

    st.markdown("### 🔍 Filters")

    # Severity filter
    filters['severities'] = st.multiselect(
        "Severity",
        options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
        default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        help="Filter vulnerabilities by severity"
    )

    # Scanner filter
    filters['scanners'] = st.multiselect(
        "Scanner",
        options=['bandit', 'safety'],
        default=['bandit', 'safety'],
        help="Filter by scanner source"
    )

    return filters


def render_date_filter(
    default_days: int = 30
) -> Tuple[datetime, datetime]:
    """
    Render a date range filter.
    
    Args:
        default_days: Default number of days to look back
        
    Returns:
        Tuple of (start_date, end_date)
    """
    st.markdown("### 📅 Date Range")

    col1, col2 = st.columns(2)

    with col1:
        start_date = st.date_input(
            "From",
            value=datetime.now() - timedelta(days=default_days),
            help="Start date for filtering"
        )

    with col2:
        end_date = st.date_input(
            "To",
            value=datetime.now(),
            help="End date for filtering"
        )

    return (
        datetime.combine(start_date, datetime.min.time()),
        datetime.combine(end_date, datetime.max.time())
    )


def render_severity_filter(
    key: str = "severity_filter"
) -> List[str]:
    """
    Render a severity multiselect filter.
    
    Args:
        key: Unique key for the widget
        
    Returns:
        List of selected severities
    """
    return st.multiselect(
        "Filter by Severity",
        options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        key=key,
        help="Select severities to display"
    )


def render_report_selector(
    reports_dir: Path,
    key: str = "report_selector"
) -> Optional[Path]:
    """
    Render a report file selector.
    
    Args:
        reports_dir: Directory containing report files
        key: Unique key for the widget
        
    Returns:
        Selected report path or None
    """
    if not reports_dir.exists():
        st.warning(f"Reports directory not found: {reports_dir}")
        return None

    reports = sorted(reports_dir.glob("audit_report_*.json"), reverse=True)

    if not reports:
        st.info("No audit reports found. Run a scan first!")
        return None

    # Create options with timestamps
    options = {}
    for report in reports:
        # Parse timestamp from filename
        name = report.stem
        try:
            timestamp = name.replace("audit_report_", "")
            display_name = f"{timestamp[:8]} {timestamp[9:11]}:{timestamp[11:13]}:{timestamp[13:15]}"
        except:
            display_name = name
        options[display_name] = report

    selected = st.selectbox(
        "Select Report",
        options=list(options.keys()),
        key=key,
        help="Choose an audit report to view"
    )

    return options.get(selected)


def render_scanner_toggle(
    key: str = "scanner_toggle"
) -> dict:
    """
    Render scanner toggle switches.
    
    Args:
        key: Base key for widgets
        
    Returns:
        Dict mapping scanner names to enabled state
    """
    st.markdown("### 🔧 Scanners")

    return {
        'bandit': st.checkbox("Bandit (SAST)", value=True, key=f"{key}_bandit", help="Static Application Security Testing"),
        'safety': st.checkbox("Safety (SCA)", value=True, key=f"{key}_safety", help="Software Composition Analysis"),
    }


def render_export_options() -> dict:
    """
    Render export format options.
    
    Returns:
        Dict with export settings
    """
    st.markdown("### 📤 Export Options")

    return {
        'format': st.selectbox(
            "Format",
            options=['JSON', 'CSV', 'PDF', 'HTML'],
            help="Select export format"
        ),
        'include_code': st.checkbox("Include code snippets", value=True),
        'include_remediation': st.checkbox("Include remediation tips", value=True),
    }


def render_threshold_settings() -> dict:
    """
    Render threshold configuration settings.
    
    Returns:
        Dict with threshold values
    """
    st.markdown("### ⚙️ Thresholds")

    return {
        'block_on_critical': st.checkbox("Block on Critical", value=True, help="Block deployment if any critical vulnerabilities found"),
        'block_on_high_count': st.number_input("Block on High Count", value=3, min_value=0, help="Block if high vulnerabilities exceed this count"),
        'max_total_score': st.number_input("Max Total Score", value=25, min_value=0, help="Block if total score exceeds this value"),
    }
