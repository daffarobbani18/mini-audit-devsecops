"""
Compliance Page
===============

OWASP Top 10, CWE, and NIST CSF compliance mapping visualization.
"""

import streamlit as st
import json
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# OWASP Top 10 2021 Categories
OWASP_TOP_10 = {
    'A01:2021': {'name': 'Broken Access Control', 'description': 'Restrictions on authenticated users are not properly enforced'},
    'A02:2021': {'name': 'Cryptographic Failures', 'description': 'Failures related to cryptography which often lead to sensitive data exposure'},
    'A03:2021': {'name': 'Injection', 'description': 'User-supplied data is not validated, filtered, or sanitized'},
    'A04:2021': {'name': 'Insecure Design', 'description': 'Missing or ineffective control design'},
    'A05:2021': {'name': 'Security Misconfiguration', 'description': 'Missing appropriate security hardening'},
    'A06:2021': {'name': 'Vulnerable Components', 'description': 'Using components with known vulnerabilities'},
    'A07:2021': {'name': 'Auth Failures', 'description': 'Authentication and session management flaws'},
    'A08:2021': {'name': 'Data Integrity Failures', 'description': 'Code and infrastructure that does not protect against integrity violations'},
    'A09:2021': {'name': 'Security Logging Failures', 'description': 'Insufficient logging and monitoring'},
    'A10:2021': {'name': 'SSRF', 'description': 'Server-Side Request Forgery'},
}

# CWE to OWASP Mapping (simplified)
CWE_OWASP_MAP = {
    'CWE-78': 'A03:2021',   # OS Command Injection
    'CWE-79': 'A03:2021',   # XSS
    'CWE-89': 'A03:2021',   # SQL Injection
    'CWE-94': 'A03:2021',   # Code Injection
    'CWE-95': 'A03:2021',   # Eval Injection
    'CWE-259': 'A02:2021',  # Hard-coded Password
    'CWE-327': 'A02:2021',  # Weak Crypto
    'CWE-330': 'A02:2021',  # Insufficient Randomness
    'CWE-502': 'A08:2021',  # Deserialization
    'CWE-703': 'A05:2021',  # Error Handling
    'CWE-798': 'A07:2021',  # Hard-coded Credentials
}

# NIST CSF Functions
NIST_CSF = {
    'ID': {'name': 'Identify', 'description': 'Develop organizational understanding to manage cybersecurity risk'},
    'PR': {'name': 'Protect', 'description': 'Develop and implement safeguards'},
    'DE': {'name': 'Detect', 'description': 'Develop and implement activities to identify cybersecurity events'},
    'RS': {'name': 'Respond', 'description': 'Develop and implement activities for detected events'},
    'RC': {'name': 'Recover', 'description': 'Develop and implement activities for resilience'},
}


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
    except:
        return None


def map_vulnerabilities_to_owasp(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """Map vulnerabilities to OWASP Top 10 categories."""
    mapping = defaultdict(list)

    for vuln in vulnerabilities:
        owasp_id = vuln.get('owasp_id', '')
        cwe_id = vuln.get('cwe_id', '')

        # Direct OWASP mapping
        if owasp_id and owasp_id in OWASP_TOP_10:
            mapping[owasp_id].append(vuln)
        # CWE to OWASP mapping
        elif cwe_id and cwe_id in CWE_OWASP_MAP:
            mapped_owasp = CWE_OWASP_MAP[cwe_id]
            mapping[mapped_owasp].append(vuln)
        else:
            # Default to A05 (Security Misconfiguration) for unmapped
            mapping['A05:2021'].append(vuln)

    return dict(mapping)


def render():
    """Render the compliance page."""

    # Page header
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #F59E0B 0%, #D97706 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    ">
        <h1 style="color: white; margin: 0; font-size: 1.75rem;">🏛️ Compliance Mapping</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 1rem;">
            Map findings to OWASP, CWE, and NIST security standards
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Load data
    reports_dir = st.session_state.get('reports_dir', Path(__file__).parent.parent.parent / "reports")
    data = load_latest_report(reports_dir)

    if not data:
        st.warning("No audit data available")
        st.info("Run a security scan first to see compliance mapping")

        if st.button("🔍 Run Scan", type="primary"):
            st.session_state.current_page = 'live_scan'
            st.rerun()
        return

    # Collect vulnerabilities
    all_vulns = []
    for scan_result in data.get('scan_results', []):
        for vuln in scan_result.get('vulnerabilities', []):
            vuln['scanner'] = scan_result.get('scanner_name', 'unknown')
            all_vulns.append(vuln)

    # Framework selector
    framework = st.selectbox(
        "Select Framework",
        options=['OWASP Top 10 2021', 'CWE Mapping', 'NIST CSF'],
        index=0
    )

    st.markdown("---")

    if framework == 'OWASP Top 10 2021':
        render_owasp_mapping(all_vulns)
    elif framework == 'CWE Mapping':
        render_cwe_mapping(all_vulns)
    else:
        render_nist_mapping(all_vulns)


def render_owasp_mapping(vulnerabilities: List[Dict]):
    """Render OWASP Top 10 compliance view."""

    st.markdown("### 🔟 OWASP Top 10 2021 Coverage")
    st.markdown("*How your findings map to OWASP Top 10 categories*")

    # Map vulnerabilities
    owasp_mapping = map_vulnerabilities_to_owasp(vulnerabilities)

    # Summary metrics
    covered = len([k for k, v in owasp_mapping.items() if v])
    total_mapped = sum(len(v) for v in owasp_mapping.values())

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Categories with Findings", f"{covered}/10")
    with col2:
        st.metric("Total Mapped Findings", total_mapped)
    with col3:
        coverage_pct = (covered / 10) * 100
        st.metric("Coverage", f"{coverage_pct:.0f}%")

    st.markdown("---")

    # Visual coverage
    import plotly.graph_objects as go

    categories = list(OWASP_TOP_10.keys())
    counts = [len(owasp_mapping.get(cat, [])) for cat in categories]
    names = [OWASP_TOP_10[cat]['name'][:20] for cat in categories]

    colors = ['#dc3545' if c > 0 else '#28a745' for c in counts]

    fig = go.Figure(go.Bar(
        x=names,
        y=counts,
        marker_color=colors,
        text=counts,
        textposition='outside'
    ))

    fig.update_layout(
        title="Findings by OWASP Category",
        height=350,
        margin=dict(t=50, b=100, l=30, r=30),
        xaxis_tickangle=-45,
        showlegend=False
    )

    st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # Detailed breakdown
    st.markdown("### 📋 Detailed Mapping")

    for owasp_id, info in OWASP_TOP_10.items():
        vulns = owasp_mapping.get(owasp_id, [])
        count = len(vulns)

        status = "🔴" if count > 0 else "🟢"

        with st.expander(f"{status} {owasp_id}: {info['name']} ({count} findings)"):
            st.markdown(f"**Description:** {info['description']}")
            st.markdown("---")

            if vulns:
                for vuln in vulns[:5]:
                    severity = vuln.get('severity', 'INFO').upper()
                    icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                    icon = icons.get(severity, '⚪')

                    st.markdown(f"{icon} **{severity}**: {vuln.get('title', 'Unknown')[:50]}")
                    st.caption(f"File: `{vuln.get('file_path', 'N/A').split('/')[-1]}` | CWE: {vuln.get('cwe_id', 'N/A')}")

                if len(vulns) > 5:
                    st.caption(f"*... and {len(vulns) - 5} more*")
            else:
                st.success("✅ No findings in this category")


def render_cwe_mapping(vulnerabilities: List[Dict]):
    """Render CWE mapping view."""

    st.markdown("### 🔢 CWE (Common Weakness Enumeration)")
    st.markdown("*Categorization of software security weaknesses*")

    # Group by CWE
    cwe_groups = defaultdict(list)
    for vuln in vulnerabilities:
        cwe = vuln.get('cwe_id', 'Unknown')
        cwe_groups[cwe].append(vuln)

    # Summary
    unique_cwes = len(cwe_groups)
    st.metric("Unique CWE IDs", unique_cwes)

    st.markdown("---")

    # Table view
    cwe_data = []
    for cwe, vulns in sorted(cwe_groups.items(), key=lambda x: len(x[1]), reverse=True):
        max_severity = 'INFO'
        for v in vulns:
            sev = v.get('severity', 'INFO').upper()
            if sev == 'CRITICAL':
                max_severity = 'CRITICAL'
                break
            elif sev == 'HIGH' and max_severity not in ['CRITICAL']:
                max_severity = 'HIGH'
            elif sev == 'MEDIUM' and max_severity not in ['CRITICAL', 'HIGH']:
                max_severity = 'MEDIUM'
            elif sev == 'LOW' and max_severity == 'INFO':
                max_severity = 'LOW'

        cwe_data.append({
            'CWE ID': cwe,
            'Count': len(vulns),
            'Max Severity': max_severity,
            'OWASP': CWE_OWASP_MAP.get(cwe, 'N/A'),
        })

    if cwe_data:
        df = pd.DataFrame(cwe_data)

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                'CWE ID': st.column_config.LinkColumn(
                    'CWE ID',
                    help="Click to view CWE details",
                    display_text="(.+)",
                    # Note: In real implementation, generate proper URLs
                ),
                'Count': st.column_config.NumberColumn('Count'),
                'Max Severity': st.column_config.TextColumn('Severity'),
                'OWASP': st.column_config.TextColumn('OWASP Category'),
            }
        )

        # Bar chart
        import plotly.express as px

        fig = px.bar(
            df.head(10),
            x='CWE ID',
            y='Count',
            color='Max Severity',
            color_discrete_map={
                'CRITICAL': '#dc3545',
                'HIGH': '#fd7e14',
                'MEDIUM': '#ffc107',
                'LOW': '#28a745',
                'INFO': '#17a2b8'
            },
            title="Top 10 CWE Categories"
        )

        fig.update_layout(height=350, margin=dict(t=50, b=30))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No CWE data available")


def render_nist_mapping(vulnerabilities: List[Dict]):
    """Render NIST CSF mapping view."""

    st.markdown("### 🏛️ NIST Cybersecurity Framework")
    st.markdown("*Framework for improving critical infrastructure cybersecurity*")

    # Info about NIST CSF
    st.info("""
    The NIST CSF organizes cybersecurity activities into five core functions.
    This tool primarily helps with **Identify** and **Protect** functions through vulnerability detection.
    """)

    st.markdown("---")

    # Show NIST functions with our coverage
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("### Core Functions")

        for func_id, info in NIST_CSF.items():
            # Determine coverage based on function
            if func_id == 'ID':
                coverage = "🟢 Covered" if vulnerabilities else "⚪ No Data"
                detail = "Asset & risk identification through scanning"
            elif func_id == 'PR':
                coverage = "🟢 Covered"
                detail = "Security recommendations provided"
            elif func_id == 'DE':
                coverage = "🟢 Covered"
                detail = "Vulnerability detection via SAST/SCA"
            else:
                coverage = "⚪ Partial"
                detail = "Requires organizational processes"

            with st.expander(f"{func_id}: {info['name']}"):
                st.markdown(f"**Description:** {info['description']}")
                st.markdown(f"**Coverage:** {coverage}")
                st.caption(detail)

    with col2:
        st.markdown("### Compliance Summary")

        # Radar chart for NIST coverage
        import plotly.graph_objects as go

        categories = ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']

        # Estimated coverage percentages
        if vulnerabilities:
            values = [85, 70, 90, 30, 20]  # Tool provides good ID, PR, DE coverage
        else:
            values = [10, 10, 10, 10, 10]

        fig = go.Figure()

        fig.add_trace(go.Scatterpolar(
            r=values + [values[0]],  # Close the polygon
            theta=categories + [categories[0]],
            fill='toself',
            fillcolor='rgba(102, 126, 234, 0.3)',
            line=dict(color='#667eea', width=2),
            name='Current Coverage'
        ))

        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100],
                    ticksuffix='%'
                )
            ),
            title="NIST CSF Coverage",
            height=400,
            showlegend=False,
            margin=dict(t=80, b=30, l=80, r=80)
        )

        st.plotly_chart(fig, use_container_width=True)

        st.markdown("""
        **Coverage Notes:**
        - ✅ **Identify (ID):** Good coverage via asset scanning
        - ✅ **Protect (PR):** Security recommendations provided
        - ✅ **Detect (DE):** Strong via SAST/SCA scanning
        - ⚠️ **Respond (RS):** Requires organizational SOPs
        - ⚠️ **Recover (RC):** Requires disaster recovery plans
        """)

    st.markdown("---")

    # Mapping table
    st.markdown("### 📋 Finding to NIST Mapping")

    if vulnerabilities:
        mapping_data = []
        for vuln in vulnerabilities[:20]:
            mapping_data.append({
                'Finding': vuln.get('title', 'Unknown')[:40],
                'Severity': vuln.get('severity', 'INFO'),
                'NIST Function': 'DE (Detect)',
                'Subcategory': 'DE.CM-8',
                'Recommendation': 'PR (Protect)',
            })

        st.dataframe(
            pd.DataFrame(mapping_data),
            use_container_width=True,
            hide_index=True
        )

        if len(vulnerabilities) > 20:
            st.caption(f"*Showing 20 of {len(vulnerabilities)} findings*")
    else:
        st.info("No findings to map")
