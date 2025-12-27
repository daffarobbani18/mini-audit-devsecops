"""
DevSecOps Gate Dashboard
========================

Streamlit-based dashboard for IT Auditors to view
security audit results and trends.

Run with:
    streamlit run dashboard/app.py
"""

import streamlit as st
import json
from pathlib import Path
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="DevSecOps Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .critical { color: #dc3545; }
    .high { color: #fd7e14; }
    .medium { color: #ffc107; }
    .low { color: #28a745; }
    .passed { color: #28a745; }
    .failed { color: #dc3545; }
</style>
""", unsafe_allow_html=True)


def load_report(file_path: Path) -> dict:
    """Load audit report from JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_available_reports(reports_dir: Path) -> list:
    """Get list of available report files."""
    if not reports_dir.exists():
        return []
    return sorted(reports_dir.glob("*.json"), reverse=True)


def main():
    """Main dashboard application."""
    
    # Header
    st.title("🛡️ DevSecOps Security Audit Dashboard")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("📁 Report Selection")
        
        reports_dir = Path(__file__).parent.parent / "reports"
        reports = get_available_reports(reports_dir)
        
        if not reports:
            st.warning("No audit reports found in `/reports` directory.")
            st.info("Run an audit first:\n```\npython scripts/run_audit.py ./src\n```")
            selected_report = None
        else:
            report_options = {f.stem: f for f in reports}
            selected_name = st.selectbox(
                "Select Report",
                options=list(report_options.keys()),
            )
            selected_report = report_options.get(selected_name)
        
        st.markdown("---")
        st.header("⚙️ Settings")
        show_details = st.checkbox("Show Vulnerability Details", value=True)
        show_remediation = st.checkbox("Show Remediation Tips", value=True)
    
    # Main content
    if selected_report:
        data = load_report(selected_report)
        display_dashboard(data, show_details, show_remediation)
    else:
        display_welcome()


def display_welcome():
    """Display welcome message when no reports available."""
    st.markdown("""
    ## 👋 Welcome to DevSecOps Audit Dashboard
    
    This dashboard provides visualization of security audit results for IT Auditors.
    
    ### Getting Started
    
    1. **Run an audit:**
       ```bash
       python scripts/run_audit.py ./your_project
       ```
    
    2. **View results:** Reports will appear in this dashboard automatically.
    
    ### Features
    
    - 📊 **Executive Summary** - High-level security metrics
    - 🔍 **Vulnerability Details** - Detailed findings with remediation
    - 📈 **Trend Analysis** - Historical security trends
    - 📋 **Compliance Mapping** - OWASP, CWE, NIST mapping
    - 📤 **Export Reports** - PDF, JSON, CSV formats
    
    ### Quick Links
    
    - [Documentation](docs/PROJECT_PHASES.md)
    - [Configuration Guide](gate_config.yaml)
    """)


def display_dashboard(data: dict, show_details: bool, show_remediation: bool):
    """Display main dashboard with audit data."""
    
    summary = data.get("summary", {})
    findings = summary.get("findings", {})
    
    # Gate Status Banner
    gate_decision = data.get("gate_decision", "UNKNOWN")
    gate_reason = data.get("gate_reason", "")
    
    if gate_decision == "PASSED":
        st.success(f"✅ **SECURITY GATE: PASSED**")
    elif gate_decision == "WARNING":
        st.warning(f"⚠️ **SECURITY GATE: WARNING**")
    else:
        st.error(f"❌ **SECURITY GATE: FAILED**")
    
    st.caption(gate_reason)
    
    # Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            label="🔴 Critical",
            value=findings.get("critical", 0),
            delta=None,
        )
    
    with col2:
        st.metric(
            label="🟠 High", 
            value=findings.get("high", 0),
        )
    
    with col3:
        st.metric(
            label="🟡 Medium",
            value=findings.get("medium", 0),
        )
    
    with col4:
        st.metric(
            label="🟢 Low",
            value=findings.get("low", 0),
        )
    
    with col5:
        st.metric(
            label="📊 Total Score",
            value=data.get("total_score", 0),
        )
    
    st.markdown("---")
    
    # Two column layout
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.subheader("📋 Audit Information")
        
        info_data = {
            "Audit ID": data.get("audit_id", "N/A"),
            "Timestamp": data.get("audit_timestamp", "N/A"),
            "Target Path": data.get("target_path", "N/A"),
            "Git Commit": data.get("git_commit", "N/A")[:8] if data.get("git_commit") else "N/A",
            "Git Branch": data.get("git_branch", "N/A"),
        }
        
        for key, value in info_data.items():
            st.text(f"{key}: {value}")
    
    with col_right:
        st.subheader("📊 Severity Distribution")
        
        import pandas as pd
        
        chart_data = pd.DataFrame({
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [
                findings.get("critical", 0),
                findings.get("high", 0),
                findings.get("medium", 0),
                findings.get("low", 0),
            ]
        })
        
        st.bar_chart(chart_data.set_index("Severity"))
    
    # Vulnerability Details
    if show_details:
        st.markdown("---")
        st.subheader("🔍 Vulnerability Details")
        
        all_vulns = []
        for scan_result in data.get("scan_results", []):
            all_vulns.extend(scan_result.get("vulnerabilities", []))
        
        if all_vulns:
            for vuln in all_vulns:
                severity = vuln.get("severity", "INFO")
                severity_colors = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠", 
                    "MEDIUM": "🟡",
                    "LOW": "🟢",
                    "INFO": "🔵",
                }
                icon = severity_colors.get(severity, "⚪")
                
                with st.expander(f"{icon} [{severity}] {vuln.get('title', 'Unknown')[:60]}"):
                    st.markdown(f"**ID:** `{vuln.get('id', 'N/A')}`")
                    st.markdown(f"**Scanner:** {vuln.get('scanner', 'N/A')}")
                    st.markdown(f"**Location:** `{vuln.get('file_path', 'N/A')}:{vuln.get('line_number', 'N/A')}`")
                    
                    if vuln.get("cwe_id"):
                        st.markdown(f"**CWE:** {vuln.get('cwe_id')}")
                    
                    if vuln.get("owasp_id"):
                        st.markdown(f"**OWASP:** {vuln.get('owasp_id')}")
                    
                    st.markdown("**Description:**")
                    st.text(vuln.get("description", "No description"))
                    
                    if vuln.get("code_snippet"):
                        st.markdown("**Code:**")
                        st.code(vuln.get("code_snippet"), language="python")
                    
                    if show_remediation and vuln.get("remediation"):
                        st.markdown("**Remediation:**")
                        st.info(vuln.get("remediation"))
        else:
            st.success("✅ No vulnerabilities found!")
    
    # Export buttons
    st.markdown("---")
    st.subheader("📤 Export")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.download_button(
            label="📥 Download JSON",
            data=json.dumps(data, indent=2),
            file_name=f"audit_report_{data.get('audit_id', 'unknown')}.json",
            mime="application/json",
        )
    
    with col2:
        # CSV export placeholder
        st.button("📥 Download CSV", disabled=True, help="Coming soon")
    
    with col3:
        # PDF export placeholder  
        st.button("📥 Download PDF", disabled=True, help="Coming soon")


if __name__ == "__main__":
    main()
