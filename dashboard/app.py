"""
DevSecOps Gate Dashboard - Main Application
============================================

Professional Streamlit dashboard for IT Auditors to visualize
security audit results, track trends, and run live scans.

Run with:
    streamlit run dashboard/app.py
    
Or with custom config:
    streamlit run dashboard/app.py -- --reports-dir ./reports
"""

import streamlit as st
from pathlib import Path

# Page configuration - MUST be first Streamlit command
st.set_page_config(
    page_title="DevSecOps Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/your-repo/mini-audit-devsecops',
        'Report a bug': 'https://github.com/your-repo/mini-audit-devsecops/issues',
        'About': '''
        ## 🛡️ DevSecOps Security Gate Dashboard
        
        **Mini Audit Tools 2025**
        
        Automated security audit visualization for IT Auditors.
        
        Features:
        - SAST Analysis (Bandit)
        - SCA Dependency Scanning (Safety)
        - OWASP/CWE/NIST Compliance Mapping
        '''
    }
)

# Initialize session state
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'overview'
if 'reports_dir' not in st.session_state:
    st.session_state.reports_dir = Path(__file__).parent.parent / "reports"
if 'selected_report' not in st.session_state:
    st.session_state.selected_report = None

# Import pages
from pages import overview, report_viewer, live_scan, trends, compliance, settings

# Custom CSS
st.markdown("""
<style>
    /* Main container */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Metric cards */
    [data-testid="metric-container"] {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 8px;
        padding: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    
    /* Status banners */
    .status-passed {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 8px;
        padding: 15px;
        color: #155724;
    }
    
    .status-failed {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 8px;
        padding: 15px;
        color: #721c24;
    }
    
    .status-warning {
        background-color: #fff3cd;
        border: 1px solid #ffeeba;
        border-radius: 8px;
        padding: 15px;
        color: #856404;
    }
    
    /* Severity colors */
    .severity-critical { color: #dc3545; font-weight: bold; }
    .severity-high { color: #fd7e14; font-weight: bold; }
    .severity-medium { color: #ffc107; font-weight: bold; }
    .severity-low { color: #28a745; font-weight: bold; }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #f8f9fa;
    }
    
    /* Navigation buttons */
    .nav-button {
        width: 100%;
        margin-bottom: 5px;
    }
    
    /* Tables */
    .dataframe {
        font-size: 14px;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #2c3e50;
    }
    
    /* Cards */
    .info-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
        padding: 20px;
        color: white;
        margin-bottom: 10px;
    }
    
    /* Footer */
    .footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        background-color: #f8f9fa;
        padding: 10px;
        text-align: center;
        font-size: 12px;
        color: #6c757d;
    }
</style>
""", unsafe_allow_html=True)


def render_sidebar():
    """Render the sidebar navigation."""
    with st.sidebar:
        # Logo and title
        st.markdown("""
        <div style="text-align: center; padding: 20px 0;">
            <h1 style="color: #2c3e50; margin: 0;">🛡️</h1>
            <h3 style="color: #2c3e50; margin: 5px 0;">DevSecOps Gate</h3>
            <p style="color: #6c757d; font-size: 12px;">Security Audit Dashboard</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # Navigation
        st.markdown("### 📍 Navigation")

        pages = {
            'overview': ('📊 Overview', 'Executive summary and metrics'),
            'report_viewer': ('📋 Report Viewer', 'Detailed vulnerability analysis'),
            'live_scan': ('🔍 Live Scan', 'Run security scans'),
            'trends': ('📈 Trends', 'Historical analysis'),
            'compliance': ('🏛️ Compliance', 'OWASP/CWE/NIST mapping'),
            'settings': ('⚙️ Settings', 'Configuration'),
        }

        for page_key, (page_name, page_desc) in pages.items():
            if st.button(
                page_name,
                key=f"nav_{page_key}",
                use_container_width=True,
                type="primary" if st.session_state.current_page == page_key else "secondary",
                help=page_desc
            ):
                st.session_state.current_page = page_key
                st.rerun()

        st.markdown("---")

        # Quick stats
        st.markdown("### 📊 Quick Stats")
        reports_count = len(list(st.session_state.reports_dir.glob("audit_report_*.json"))) if st.session_state.reports_dir.exists() else 0
        st.metric("Total Reports", reports_count)

        st.markdown("---")

        # Info
        st.markdown("""
        <div style="text-align: center; font-size: 11px; color: #6c757d;">
            <p>Mini Audit Tools 2025</p>
            <p>v1.0.0 | Capstone IT Audit</p>
        </div>
        """, unsafe_allow_html=True)


def main():
    """Main application entry point."""

    # Render sidebar
    render_sidebar()

    # Route to current page
    page_map = {
        'overview': overview.render,
        'report_viewer': report_viewer.render,
        'live_scan': live_scan.render,
        'trends': trends.render,
        'compliance': compliance.render,
        'settings': settings.render,
    }

    current_page = st.session_state.current_page

    if current_page in page_map:
        page_map[current_page]()
    else:
        overview.render()


if __name__ == "__main__":
    main()
