"""
Table Components
================

Data table components for displaying vulnerabilities and findings.
"""

import streamlit as st
import pandas as pd
from typing import List, Dict, Optional


SEVERITY_ICONS = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢',
    'INFO': '🔵',
}

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']


def render_vulnerability_table(
    vulnerabilities: List[Dict],
    show_code: bool = False,
    show_remediation: bool = True,
    severity_filter: Optional[List[str]] = None,
    max_items: int = 100
) -> None:
    """
    Render a table of vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        show_code: Whether to show code snippets
        show_remediation: Whether to show remediation tips
        severity_filter: Optional list of severities to show
        max_items: Maximum items to display
    """
    if not vulnerabilities:
        st.success("✅ No vulnerabilities found!")
        return

    # Apply severity filter
    if severity_filter:
        vulnerabilities = [v for v in vulnerabilities if v.get('severity', '').upper() in severity_filter]

    # Sort by severity
    def severity_sort_key(v):
        sev = v.get('severity', 'INFO').upper()
        return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)

    vulnerabilities = sorted(vulnerabilities, key=severity_sort_key)[:max_items]

    st.markdown(f"**Showing {len(vulnerabilities)} vulnerabilities**")

    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'INFO').upper()
        icon = SEVERITY_ICONS.get(severity, '⚪')
        title = vuln.get('title', 'Unknown Issue')[:60]

        with st.expander(f"{icon} **[{severity}]** {title}", expanded=False):
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown(f"**ID:** `{vuln.get('id', 'N/A')}`")
                st.markdown(f"**Scanner:** {vuln.get('scanner', 'N/A')}")
                st.markdown(f"**Location:** `{vuln.get('file_path', 'N/A')}:{vuln.get('line_number', 'N/A')}`")

                if vuln.get('description'):
                    st.markdown("**Description:**")
                    st.text(vuln.get('description'))

            with col2:
                if vuln.get('cwe_id'):
                    st.markdown(f"**CWE:** [{vuln.get('cwe_id')}](https://cwe.mitre.org/data/definitions/{vuln.get('cwe_id').replace('CWE-', '')}.html)")

                if vuln.get('owasp_id'):
                    st.markdown(f"**OWASP:** {vuln.get('owasp_id')}")

                confidence = vuln.get('confidence', 'N/A')
                st.markdown(f"**Confidence:** {confidence}")

            if show_code and vuln.get('code_snippet'):
                st.markdown("**Code:**")
                st.code(vuln.get('code_snippet'), language='python')

            if show_remediation and vuln.get('remediation'):
                st.markdown("**Remediation:**")
                st.info(vuln.get('remediation'))


def render_vulnerability_dataframe(
    vulnerabilities: List[Dict],
    severity_filter: Optional[List[str]] = None
) -> Optional[pd.DataFrame]:
    """
    Render vulnerabilities as an interactive dataframe.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        severity_filter: Optional severity filter
        
    Returns:
        The rendered DataFrame or None
    """
    if not vulnerabilities:
        st.info("No vulnerabilities to display")
        return None

    # Convert to DataFrame
    df_data = []
    for v in vulnerabilities:
        severity = v.get('severity', 'INFO').upper()

        if severity_filter and severity not in severity_filter:
            continue

        df_data.append({
            'Severity': f"{SEVERITY_ICONS.get(severity, '⚪')} {severity}",
            'Title': v.get('title', 'Unknown')[:50],
            'File': v.get('file_path', 'N/A').split('/')[-1],
            'Line': v.get('line_number', 'N/A'),
            'Scanner': v.get('scanner', 'N/A'),
            'CWE': v.get('cwe_id', 'N/A'),
        })

    if not df_data:
        st.info("No vulnerabilities match the filter")
        return None

    df = pd.DataFrame(df_data)

    # Display as interactive table
    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            'Severity': st.column_config.TextColumn('Severity', width='small'),
            'Title': st.column_config.TextColumn('Title', width='large'),
            'File': st.column_config.TextColumn('File', width='medium'),
            'Line': st.column_config.NumberColumn('Line', width='small'),
            'Scanner': st.column_config.TextColumn('Scanner', width='small'),
            'CWE': st.column_config.TextColumn('CWE', width='small'),
        }
    )

    return df


def render_compliance_table(
    vulnerabilities: List[Dict],
    framework: str = 'all'
) -> None:
    """
    Render compliance mapping table.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        framework: 'owasp', 'cwe', 'nist', or 'all'
    """
    if not vulnerabilities:
        st.info("No vulnerabilities to map")
        return

    # Build compliance mapping
    owasp_mapping = {}
    cwe_mapping = {}

    for v in vulnerabilities:
        # CWE mapping
        cwe = v.get('cwe_id', 'Unknown')
        if cwe not in cwe_mapping:
            cwe_mapping[cwe] = {'count': 0, 'severities': []}
        cwe_mapping[cwe]['count'] += 1
        cwe_mapping[cwe]['severities'].append(v.get('severity', 'INFO'))

        # OWASP mapping
        owasp = v.get('owasp_id', 'Unknown')
        if owasp not in owasp_mapping:
            owasp_mapping[owasp] = {'count': 0, 'severities': []}
        owasp_mapping[owasp]['count'] += 1
        owasp_mapping[owasp]['severities'].append(v.get('severity', 'INFO'))

    if framework in ['cwe', 'all']:
        st.markdown("#### CWE Mapping")
        cwe_df = pd.DataFrame([
            {
                'CWE ID': cwe,
                'Count': data['count'],
                'Highest Severity': max(data['severities'], key=lambda x: SEVERITY_ORDER.index(x.upper()) if x.upper() in SEVERITY_ORDER else 999)
            }
            for cwe, data in sorted(cwe_mapping.items(), key=lambda x: x[1]['count'], reverse=True)
        ])
        st.dataframe(cwe_df, use_container_width=True, hide_index=True)

    if framework in ['owasp', 'all']:
        st.markdown("#### OWASP Top 10 Mapping")
        owasp_df = pd.DataFrame([
            {
                'OWASP Category': owasp,
                'Count': data['count'],
                'Highest Severity': max(data['severities'], key=lambda x: SEVERITY_ORDER.index(x.upper()) if x.upper() in SEVERITY_ORDER else 999)
            }
            for owasp, data in sorted(owasp_mapping.items(), key=lambda x: x[1]['count'], reverse=True)
        ])
        st.dataframe(owasp_df, use_container_width=True, hide_index=True)


def render_file_summary_table(vulnerabilities: List[Dict]) -> None:
    """
    Render a summary table grouped by file.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    """
    if not vulnerabilities:
        st.info("No vulnerabilities to summarize")
        return

    # Group by file
    file_summary = {}
    for v in vulnerabilities:
        file_path = v.get('file_path', 'Unknown')
        if file_path not in file_summary:
            file_summary[file_path] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}

        severity = v.get('severity', 'INFO').lower()
        if severity in file_summary[file_path]:
            file_summary[file_path][severity] += 1
        file_summary[file_path]['total'] += 1

    # Convert to DataFrame
    df = pd.DataFrame([
        {
            'File': path.split('/')[-1],
            'Full Path': path,
            '🔴 Critical': data['critical'],
            '🟠 High': data['high'],
            '🟡 Medium': data['medium'],
            '🟢 Low': data['low'],
            'Total': data['total'],
        }
        for path, data in sorted(file_summary.items(), key=lambda x: x[1]['total'], reverse=True)
    ])

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
        column_config={
            'File': st.column_config.TextColumn('File', width='medium'),
            'Full Path': st.column_config.TextColumn('Full Path', width='large'),
            '🔴 Critical': st.column_config.NumberColumn('Critical', width='small'),
            '🟠 High': st.column_config.NumberColumn('High', width='small'),
            '🟡 Medium': st.column_config.NumberColumn('Medium', width='small'),
            '🟢 Low': st.column_config.NumberColumn('Low', width='small'),
            'Total': st.column_config.NumberColumn('Total', width='small'),
        }
    )
