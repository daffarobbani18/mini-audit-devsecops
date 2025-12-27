"""
Overview Page
=============

Executive summary dashboard showing high-level security metrics.
"""

import streamlit as st
import json
from pathlib import Path
from typing import Optional, Dict, List

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.components.metrics import render_gate_status_banner, render_kpi_cards, render_audit_info
from dashboard.components.charts import render_severity_pie_chart, render_scanner_comparison


def load_latest_report(reports_dir: Path) -> Optional[Dict]:
    """Load the most recent audit report."""
    if not reports_dir.exists():
        return None

    reports = sorted(reports_dir.glob("audit_report_*.json"), reverse=True)
    if not reports:
        return None

    try:
        with open(reports[0], 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading report: {e}")
        return None


def load_all_reports(reports_dir: Path, limit: int = 10) -> List[Dict]:
    """Load multiple reports for trend analysis."""
    if not reports_dir.exists():
        return []

    reports = sorted(reports_dir.glob("audit_report_*.json"), reverse=True)[:limit]
    loaded = []

    for report_path in reports:
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                loaded.append(json.load(f))
        except:
            continue

    return loaded


def render():
    """Render the overview page."""

    # Page header with gradient
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #4F46E5 0%, #3730A3 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    ">
        <h1 style="color: white; margin: 0; font-size: 1.75rem;">📊 Security Overview</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 1rem;">
            Executive summary of your security posture
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Load latest report
    reports_dir = st.session_state.get('reports_dir', Path(__file__).parent.parent.parent / "reports")
    data = load_latest_report(reports_dir)

    if not data:
        render_welcome()
        return

    # Gate Status Banner
    gate_decision = data.get('gate_decision', 'UNKNOWN')
    gate_reason = data.get('gate_reason', '')
    render_gate_status_banner(gate_decision, gate_reason)

    st.markdown("")

    # KPI Cards
    summary = data.get('summary', {})
    findings = summary.get('findings', {})
    total_score = data.get('total_score', 0)

    render_kpi_cards(findings, total_score)

    st.markdown("---")

    # Charts Row
    col1, col2 = st.columns(2)

    with col1:
        render_severity_pie_chart(findings, "Severity Distribution")

    with col2:
        # Scanner comparison
        scan_results = data.get('scan_results', [])
        render_scanner_comparison(scan_results, "Findings by Scanner")

    st.markdown("---")

    # Audit Info and Quick Actions
    col_left, col_right = st.columns([2, 1])

    with col_left:
        render_audit_info(data)

    with col_right:
        st.markdown("### ⚡ Quick Actions")

        if st.button("🔍 Run New Scan", use_container_width=True, type="primary"):
            st.session_state.current_page = 'live_scan'
            st.rerun()

        if st.button("📋 View Full Report", use_container_width=True):
            st.session_state.current_page = 'report_viewer'
            st.rerun()

        if st.button("📈 View Trends", use_container_width=True):
            st.session_state.current_page = 'trends'
            st.rerun()

        # Export button
        st.markdown("---")
        st.download_button(
            label="📥 Export JSON",
            data=json.dumps(data, indent=2, default=str),
            file_name=f"audit_{data.get('audit_id', 'report')}.json",
            mime="application/json",
            use_container_width=True
        )

    # Recent Findings Summary
    st.markdown("---")
    st.markdown("### 🔍 Top Findings")

    all_vulns = []
    for scan_result in data.get('scan_results', []):
        all_vulns.extend(scan_result.get('vulnerabilities', []))

    if all_vulns:
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'INFO').upper(), 5))

        # Show top 5
        for vuln in all_vulns[:5]:
            severity = vuln.get('severity', 'INFO').upper()
            icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}
            icon = icons.get(severity, '⚪')

            col1, col2, col3 = st.columns([1, 4, 2])
            with col1:
                st.markdown(f"**{icon} {severity}**")
            with col2:
                st.markdown(vuln.get('title', 'Unknown')[:50])
            with col3:
                st.caption(f"`{vuln.get('file_path', 'N/A').split('/')[-1]}:{vuln.get('line_number', 'N/A')}`")

        if len(all_vulns) > 5:
            st.caption(f"*... and {len(all_vulns) - 5} more findings*")
    else:
        st.success("✅ No vulnerabilities detected!")


def render_welcome():
    """Display welcome message when no reports available."""

    st.markdown("""
    <div style="
        text-align: center;
        padding: 3rem 2rem;
        background: linear-gradient(135deg, #F8FAFC 0%, #F1F5F9 100%);
        border-radius: 16px;
        border: 2px dashed #CBD5E1;
        margin: 2rem 0;
    ">
        <div style="font-size: 4rem; margin-bottom: 1rem;">👋</div>
        <h2 style="color: #1E293B; margin: 0 0 0.5rem 0;">Welcome to DevSecOps Gate!</h2>
        <p style="color: #64748B; font-size: 1.1rem; margin: 0;">
            No audit reports found yet. Let's run your first security scan!
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        st.markdown("""
        ### 🚀 Getting Started

        **Option 1: Run from Dashboard**

        Click the button below to run a security scan directly from the dashboard.
        """)

        if st.button("🔍 Run Security Scan", type="primary", use_container_width=True):
            st.session_state.current_page = 'live_scan'
            st.rerun()

        st.markdown("""
        ---

        **Option 2: Run from Command Line**

        ```bash
        python scripts/run_audit.py ./your_project
        ```

        ---

        **Option 3: CI/CD Integration**

        Push your code to GitHub and let the automated pipeline run the scan!
        """)

        st.markdown("""
        ---
        
        ### 📚 Resources
        
        - [📖 Documentation](docs/PROJECT_PHASES.md)
        - [⚙️ Configuration Guide](gate_config.yaml)
        - [🔧 GitHub Actions Setup](.github/workflows/security-gate.yml)
        """)
