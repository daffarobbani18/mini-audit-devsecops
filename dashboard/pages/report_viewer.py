"""
Report Viewer Page
==================

Detailed view of audit reports with filtering and analysis.
"""

import streamlit as st
import json
import pandas as pd
from pathlib import Path
from typing import Optional, Dict, List

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.components.tables import (
    render_vulnerability_table,
    render_vulnerability_dataframe,
    render_file_summary_table
)
from dashboard.components.charts import render_severity_bar_chart
from dashboard.components.metrics import render_gate_status_banner, render_kpi_cards


def get_available_reports(reports_dir: Path) -> List[Path]:
    """Get list of available report files."""
    if not reports_dir.exists():
        return []
    return sorted(reports_dir.glob("audit_report_*.json"), reverse=True)


def load_report(file_path: Path) -> Optional[Dict]:
    """Load audit report from JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading report: {e}")
        return None


def render():
    """Render the report viewer page."""

    # Page header
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #0EA5E9 0%, #0284C7 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    ">
        <h1 style="color: white; margin: 0; font-size: 1.75rem;">📋 Report Viewer</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 1rem;">
            Detailed vulnerability analysis and filtering
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar filters
    with st.sidebar:
        st.markdown("### 📁 Report Selection")

        reports_dir = st.session_state.get('reports_dir', Path(__file__).parent.parent.parent / "reports")
        reports = get_available_reports(reports_dir)

        if not reports:
            st.warning("No reports found")
            st.info("Run an audit first!")
            return

        # Report selector
        report_options = {}
        for r in reports:
            name = r.stem.replace("audit_report_", "")
            try:
                display = f"{name[:8]} {name[9:11]}:{name[11:13]}"
            except:
                display = name
            report_options[display] = r

        selected_name = st.selectbox(
            "Select Report",
            options=list(report_options.keys()),
            key="report_viewer_selector"
        )
        selected_report = report_options.get(selected_name)

        st.markdown("---")

        # Filters
        st.markdown("### 🔍 Filters")

        severity_filter = st.multiselect(
            "Severity",
            options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            key="severity_filter"
        )

        scanner_filter = st.multiselect(
            "Scanner",
            options=['bandit', 'safety'],
            default=['bandit', 'safety'],
            key="scanner_filter"
        )

        st.markdown("---")

        # Display options
        st.markdown("### 👁️ Display")

        show_code = st.checkbox("Show code snippets", value=False)
        show_remediation = st.checkbox("Show remediation", value=True)
        view_mode = st.radio(
            "View Mode",
            options=['Cards', 'Table', 'By File'],
            index=0
        )

    # Load selected report
    if not selected_report:
        st.info("Please select a report")
        return

    data = load_report(selected_report)
    if not data:
        return

    # Header with gate status
    col1, col2 = st.columns([3, 1])

    with col1:
        gate_decision = data.get('gate_decision', 'UNKNOWN')
        gate_reason = data.get('gate_reason', '')
        render_gate_status_banner(gate_decision, gate_reason)

    with col2:
        st.metric("Audit ID", data.get('audit_id', 'N/A'))

    st.markdown("")

    # Summary metrics
    summary = data.get('summary', {})
    findings = summary.get('findings', {})
    render_kpi_cards(findings, data.get('total_score', 0))

    st.markdown("---")

    # Collect all vulnerabilities
    all_vulns = []
    for scan_result in data.get('scan_results', []):
        scanner_name = scan_result.get('scanner_name', 'unknown')

        # Apply scanner filter
        if scanner_name not in scanner_filter:
            continue

        for vuln in scan_result.get('vulnerabilities', []):
            vuln['scanner'] = scanner_name
            all_vulns.append(vuln)

    # Apply severity filter
    filtered_vulns = [
        v for v in all_vulns
        if v.get('severity', 'INFO').upper() in severity_filter
    ]

    # Stats
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Findings", len(all_vulns))
    with col2:
        st.metric("Filtered", len(filtered_vulns))
    with col3:
        st.metric("Scanners", len(data.get('scan_results', [])))

    st.markdown("---")

    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📋 Vulnerabilities", "📊 Analysis", "📤 Export"])

    with tab1:
        if not filtered_vulns:
            st.success("✅ No vulnerabilities match the current filters!")
        else:
            if view_mode == 'Cards':
                render_vulnerability_table(
                    filtered_vulns,
                    show_code=show_code,
                    show_remediation=show_remediation
                )
            elif view_mode == 'Table':
                render_vulnerability_dataframe(filtered_vulns)
            else:  # By File
                render_file_summary_table(filtered_vulns)

    with tab2:
        if filtered_vulns:
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Severity Distribution")
                severity_counts = {}
                for v in filtered_vulns:
                    sev = v.get('severity', 'INFO').lower()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                render_severity_bar_chart(severity_counts)

            with col2:
                st.markdown("#### By Scanner")
                scanner_counts = {}
                for v in filtered_vulns:
                    scanner = v.get('scanner', 'unknown')
                    scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

                for scanner, count in scanner_counts.items():
                    st.metric(scanner.capitalize(), count)

            # File heatmap
            st.markdown("#### Findings by File")
            render_file_summary_table(filtered_vulns)
        else:
            st.info("No data to analyze")

    with tab3:
        st.markdown("### 📤 Export Report")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.download_button(
                label="📥 JSON (Full)",
                data=json.dumps(data, indent=2, default=str),
                file_name=f"audit_{data.get('audit_id', 'report')}.json",
                mime="application/json",
                use_container_width=True
            )

        with col2:
            # CSV export
            if filtered_vulns:
                df = pd.DataFrame([{
                    'Severity': v.get('severity', 'INFO'),
                    'Title': v.get('title', 'Unknown'),
                    'File': v.get('file_path', 'N/A'),
                    'Line': v.get('line_number', 'N/A'),
                    'Scanner': v.get('scanner', 'N/A'),
                    'CWE': v.get('cwe_id', 'N/A'),
                    'Description': v.get('description', '')[:100],
                } for v in filtered_vulns])

                csv = df.to_csv(index=False)
                st.download_button(
                    label="📥 CSV",
                    data=csv,
                    file_name=f"vulnerabilities_{data.get('audit_id', 'report')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            else:
                st.button("📥 CSV", disabled=True, use_container_width=True)

        with col3:
            # Summary export
            summary_data = {
                'audit_id': data.get('audit_id'),
                'timestamp': data.get('audit_timestamp'),
                'gate_decision': data.get('gate_decision'),
                'total_score': data.get('total_score'),
                'findings': findings,
                'vulnerability_count': len(all_vulns),
            }
            st.download_button(
                label="📥 Summary JSON",
                data=json.dumps(summary_data, indent=2, default=str),
                file_name=f"summary_{data.get('audit_id', 'report')}.json",
                mime="application/json",
                use_container_width=True
            )
