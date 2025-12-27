"""
Metric Components
=================

Display components for metrics and KPIs.
"""

import streamlit as st
from typing import Optional, Dict, Any


def render_metric_card(
    label: str,
    value: Any,
    delta: Optional[Any] = None,
    delta_color: str = "normal",
    help_text: Optional[str] = None,
    icon: Optional[str] = None
) -> None:
    """
    Render a single metric card.
    
    Args:
        label: Metric label
        value: Metric value
        delta: Optional delta value for comparison
        delta_color: 'normal', 'inverse', or 'off'
        help_text: Optional help tooltip
        icon: Optional emoji icon
    """
    display_label = f"{icon} {label}" if icon else label
    
    st.metric(
        label=display_label,
        value=value,
        delta=delta,
        delta_color=delta_color,
        help=help_text
    )


def render_metric_row(
    metrics: Dict[str, Dict],
    columns: int = 4
) -> None:
    """
    Render a row of metrics.
    
    Args:
        metrics: Dict mapping metric names to their configs
                 Each config should have: value, icon, delta (optional), help (optional)
        columns: Number of columns
    """
    cols = st.columns(columns)
    
    for idx, (name, config) in enumerate(metrics.items()):
        with cols[idx % columns]:
            render_metric_card(
                label=name,
                value=config.get('value', 0),
                delta=config.get('delta'),
                delta_color=config.get('delta_color', 'normal'),
                help_text=config.get('help'),
                icon=config.get('icon')
            )


def render_gate_status_banner(
    decision: str,
    reason: str = "",
    show_icon: bool = True
) -> None:
    """
    Render a gate status banner.
    
    Args:
        decision: 'PASSED', 'WARNING', 'FAILED', or 'ERROR'
        reason: Explanation for the decision
        show_icon: Whether to show the status icon
    """
    icons = {
        'PASSED': '✅',
        'WARNING': '⚠️',
        'FAILED': '❌',
        'ERROR': '🚫',
    }
    
    messages = {
        'PASSED': 'SECURITY GATE: PASSED',
        'WARNING': 'SECURITY GATE: WARNING',
        'FAILED': 'SECURITY GATE: FAILED',
        'ERROR': 'SECURITY GATE: ERROR',
    }
    
    icon = icons.get(decision, '❓') if show_icon else ''
    message = messages.get(decision, 'SECURITY GATE: UNKNOWN')
    
    if decision == 'PASSED':
        st.success(f"{icon} **{message}**")
    elif decision == 'WARNING':
        st.warning(f"{icon} **{message}**")
    elif decision == 'FAILED':
        st.error(f"{icon} **{message}**")
    else:
        st.info(f"{icon} **{message}**")
    
    if reason:
        st.caption(reason)


def render_kpi_cards(
    findings: Dict[str, int],
    total_score: int,
    threshold: int = 25
) -> None:
    """
    Render KPI cards for executive summary.
    
    Args:
        findings: Dict with severity counts
        total_score: Total risk score
        threshold: Score threshold for comparison
    """
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        critical = findings.get('critical', 0)
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: {'#f8d7da' if critical > 0 else '#d4edda'}; border-radius: 8px;">
            <h3 style="margin: 0; color: {'#721c24' if critical > 0 else '#155724'};">🔴 {critical}</h3>
            <p style="margin: 5px 0 0 0; font-size: 12px; color: #6c757d;">Critical</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        high = findings.get('high', 0)
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: {'#fff3cd' if high > 0 else '#d4edda'}; border-radius: 8px;">
            <h3 style="margin: 0; color: {'#856404' if high > 0 else '#155724'};">🟠 {high}</h3>
            <p style="margin: 5px 0 0 0; font-size: 12px; color: #6c757d;">High</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        medium = findings.get('medium', 0)
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
            <h3 style="margin: 0; color: #856404;">🟡 {medium}</h3>
            <p style="margin: 5px 0 0 0; font-size: 12px; color: #6c757d;">Medium</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        low = findings.get('low', 0)
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
            <h3 style="margin: 0; color: #28a745;">🟢 {low}</h3>
            <p style="margin: 5px 0 0 0; font-size: 12px; color: #6c757d;">Low</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        score_color = '#721c24' if total_score > threshold else '#155724'
        score_bg = '#f8d7da' if total_score > threshold else '#d4edda'
        st.markdown(f"""
        <div style="text-align: center; padding: 15px; background: {score_bg}; border-radius: 8px;">
            <h3 style="margin: 0; color: {score_color};">📊 {total_score}</h3>
            <p style="margin: 5px 0 0 0; font-size: 12px; color: #6c757d;">Risk Score</p>
        </div>
        """, unsafe_allow_html=True)


def render_audit_info(audit_data: Dict) -> None:
    """
    Render audit information in a clean format.
    
    Args:
        audit_data: Dict containing audit metadata
    """
    st.markdown("### 📋 Audit Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"""
        | Field | Value |
        |-------|-------|
        | **Audit ID** | `{audit_data.get('audit_id', 'N/A')}` |
        | **Timestamp** | {audit_data.get('audit_timestamp', 'N/A')} |
        | **Target Path** | `{audit_data.get('target_path', 'N/A')}` |
        """)
    
    with col2:
        git_commit = audit_data.get('git_commit', '')
        git_branch = audit_data.get('git_branch', 'N/A')
        st.markdown(f"""
        | Field | Value |
        |-------|-------|
        | **Git Branch** | `{git_branch}` |
        | **Git Commit** | `{git_commit[:8] if git_commit else 'N/A'}` |
        | **Scanners** | Bandit, Safety |
        """)
