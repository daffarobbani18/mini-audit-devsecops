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
        bg_color = 'rgba(220, 38, 38, 0.1)' if critical > 0 else 'rgba(22, 163, 74, 0.1)'
        text_color = '#DC2626' if critical > 0 else '#16A34A'
        border_color = 'rgba(220, 38, 38, 0.3)' if critical > 0 else 'rgba(22, 163, 74, 0.3)'
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1.25rem 1rem;
            background: {bg_color};
            border: 1px solid {border_color};
            border-radius: 12px;
            transition: transform 0.2s ease;
        ">
            <div style="font-size: 2rem; font-weight: 700; color: {text_color};">{critical}</div>
            <div style="font-size: 0.75rem; font-weight: 500; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em;">Critical</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        high = findings.get('high', 0)
        bg_color = 'rgba(234, 88, 12, 0.1)' if high > 0 else 'rgba(22, 163, 74, 0.1)'
        text_color = '#EA580C' if high > 0 else '#16A34A'
        border_color = 'rgba(234, 88, 12, 0.3)' if high > 0 else 'rgba(22, 163, 74, 0.3)'
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1.25rem 1rem;
            background: {bg_color};
            border: 1px solid {border_color};
            border-radius: 12px;
        ">
            <div style="font-size: 2rem; font-weight: 700; color: {text_color};">{high}</div>
            <div style="font-size: 0.75rem; font-weight: 500; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em;">High</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        medium = findings.get('medium', 0)
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1.25rem 1rem;
            background: rgba(217, 119, 6, 0.1);
            border: 1px solid rgba(217, 119, 6, 0.3);
            border-radius: 12px;
        ">
            <div style="font-size: 2rem; font-weight: 700; color: #D97706;">{medium}</div>
            <div style="font-size: 0.75rem; font-weight: 500; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em;">Medium</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        low = findings.get('low', 0)
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1.25rem 1rem;
            background: rgba(22, 163, 74, 0.1);
            border: 1px solid rgba(22, 163, 74, 0.3);
            border-radius: 12px;
        ">
            <div style="font-size: 2rem; font-weight: 700; color: #16A34A;">{low}</div>
            <div style="font-size: 0.75rem; font-weight: 500; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em;">Low</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        score_color = '#DC2626' if total_score > threshold else '#16A34A'
        bg_color = 'rgba(220, 38, 38, 0.1)' if total_score > threshold else 'rgba(22, 163, 74, 0.1)'
        border_color = 'rgba(220, 38, 38, 0.3)' if total_score > threshold else 'rgba(22, 163, 74, 0.3)'
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1.25rem 1rem;
            background: {bg_color};
            border: 1px solid {border_color};
            border-radius: 12px;
        ">
            <div style="font-size: 2rem; font-weight: 700; color: {score_color};">{total_score}</div>
            <div style="font-size: 0.75rem; font-weight: 500; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em;">Risk Score</div>
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
