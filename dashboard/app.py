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
    page_title="DevSecOps Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/your-repo/mini-audit-devsecops',
        'Report a bug': 'https://github.com/your-repo/mini-audit-devsecops/issues',
        'About': '''
## 🛡️ DevSecOps Security Gate

**Mini Audit Tools 2025** | Capstone IT Audit

Automated security audit visualization for IT Auditors.

**Features:**
- 🔍 SAST Analysis (Bandit)
- 📦 SCA Dependency Scanning (Safety)
- 🏛️ OWASP/CWE/NIST Compliance Mapping
- 📊 Real-time Dashboard & Trends
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

# Import and apply custom theme
from styles.theme import get_custom_css, COLORS
st.markdown(get_custom_css(), unsafe_allow_html=True)


def render_sidebar():
    """Render the sidebar navigation with modern design."""
    with st.sidebar:
        # Logo and title with gradient background
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1.5rem 1rem;
            margin: -1rem -1rem 1rem -1rem;
            background: linear-gradient(135deg, {COLORS['primary']} 0%, {COLORS['primary_dark']} 100%);
            border-radius: 0 0 16px 16px;
        ">
            <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🛡️</div>
            <h2 style="color: white; margin: 0; font-size: 1.25rem; font-weight: 600;">DevSecOps Gate</h2>
            <p style="color: rgba(255,255,255,0.8); font-size: 0.75rem; margin: 0.25rem 0 0 0;">Security Audit Dashboard</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("")

        # Navigation section
        st.markdown(f"""
        <p style="
            font-size: 0.7rem;
            font-weight: 600;
            color: {COLORS['text_muted']};
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.5rem;
        ">Navigation</p>
        """, unsafe_allow_html=True)

        pages = {
            'overview': ('📊', 'Overview', 'Executive summary and metrics'),
            'report_viewer': ('📋', 'Report Viewer', 'Detailed vulnerability analysis'),
            'live_scan': ('🔍', 'Live Scan', 'Run security scans'),
            'trends': ('📈', 'Trends', 'Historical analysis'),
            'compliance': ('🏛️', 'Compliance', 'OWASP/CWE/NIST mapping'),
            'settings': ('⚙️', 'Settings', 'Configuration'),
        }

        for page_key, (icon, page_name, page_desc) in pages.items():
            is_active = st.session_state.current_page == page_key
            if st.button(
                f"{icon}  {page_name}",
                key=f"nav_{page_key}",
                use_container_width=True,
                type="primary" if is_active else "secondary",
                help=page_desc
            ):
                st.session_state.current_page = page_key
                st.rerun()

        st.markdown("")
        st.markdown("---")

        # Quick stats section
        st.markdown(f"""
        <p style="
            font-size: 0.7rem;
            font-weight: 600;
            color: {COLORS['text_muted']};
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.5rem;
        ">Quick Stats</p>
        """, unsafe_allow_html=True)

        reports_count = len(list(st.session_state.reports_dir.glob("audit_report_*.json"))) if st.session_state.reports_dir.exists() else 0

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Reports", reports_count)
        with col2:
            st.metric("Scanners", "2")

        st.markdown("---")

        # Footer info
        st.markdown(f"""
        <div style="
            text-align: center;
            padding: 1rem 0;
            border-top: 1px solid {COLORS['border_light']};
        ">
            <p style="font-size: 0.7rem; color: {COLORS['text_muted']}; margin: 0;">
                <strong>Mini Audit Tools 2025</strong>
            </p>
            <p style="font-size: 0.65rem; color: {COLORS['text_muted']}; margin: 0.25rem 0 0 0;">
                v1.0.0 • Capstone IT Audit
            </p>
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
