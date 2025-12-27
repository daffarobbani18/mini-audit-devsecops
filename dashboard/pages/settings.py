"""
Settings Page
=============

Configuration and settings management for the dashboard.
"""

import streamlit as st
import yaml
from pathlib import Path
from typing import Dict, Any

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not config_path.exists():
        return {}

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        st.error(f"Error loading config: {e}")
        return {}


def save_config(config_path: Path, config: Dict[str, Any]) -> bool:
    """Save configuration to YAML file."""
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        st.error(f"Error saving config: {e}")
        return False


def render():
    """Render the settings page."""

    # Page header
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #64748B 0%, #475569 100%);
        padding: 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    ">
        <h1 style="color: white; margin: 0; font-size: 1.75rem;">⚙️ Settings</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0; font-size: 1rem;">
            Configure the DevSecOps Security Gate
        </p>
    </div>
    """, unsafe_allow_html=True)

    project_root = Path(__file__).parent.parent.parent
    config_path = project_root / "gate_config.yaml"

    # Load current config
    config = load_config(config_path)
    gate_config = config.get('gate', {})

    # Tabs for different settings
    tab1, tab2, tab3, tab4 = st.tabs([
        "🎚️ Thresholds",
        "🔧 Scanners",
        "📁 Paths",
        "📋 About"
    ])

    with tab1:
        render_threshold_settings(gate_config)

    with tab2:
        render_scanner_settings(gate_config)

    with tab3:
        render_path_settings()

    with tab4:
        render_about()


def render_threshold_settings(gate_config: Dict):
    """Render threshold configuration."""

    st.markdown("### 🎚️ Security Gate Thresholds")
    st.markdown("*Configure when the security gate should block deployment*")

    thresholds = gate_config.get('thresholds', {})

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Blocking Rules")

        block_critical = st.checkbox(
            "Block on Critical",
            value=thresholds.get('block_on_critical', True),
            help="Block deployment if ANY critical vulnerability is found"
        )

        block_high_count = st.number_input(
            "Block on High Count",
            min_value=0,
            max_value=100,
            value=thresholds.get('block_on_high_count', 3),
            help="Block if HIGH vulnerabilities >= this count"
        )

        block_medium_count = st.number_input(
            "Block on Medium Count",
            min_value=0,
            max_value=100,
            value=thresholds.get('block_on_medium_count', 10),
            help="Block if MEDIUM vulnerabilities >= this count"
        )

        max_score = st.number_input(
            "Max Total Score",
            min_value=0,
            max_value=1000,
            value=thresholds.get('max_total_score', 25),
            help="Block if total risk score exceeds this value"
        )

    with col2:
        st.markdown("#### Score Weights")
        st.caption("Points assigned to each severity level")

        critical_score = st.slider(
            "Critical Score",
            min_value=0,
            max_value=20,
            value=thresholds.get('critical_score', 10)
        )

        high_score = st.slider(
            "High Score",
            min_value=0,
            max_value=20,
            value=thresholds.get('high_score', 8)
        )

        medium_score = st.slider(
            "Medium Score",
            min_value=0,
            max_value=20,
            value=thresholds.get('medium_score', 5)
        )

        low_score = st.slider(
            "Low Score",
            min_value=0,
            max_value=20,
            value=thresholds.get('low_score', 2)
        )

    # Preview
    st.markdown("---")
    st.markdown("#### 📊 Score Preview")

    example_col1, example_col2, example_col3 = st.columns(3)

    with example_col1:
        st.markdown("**Example 1:** 1 Critical")
        score1 = 1 * critical_score
        status1 = "❌ BLOCKED" if block_critical or score1 > max_score else "✅ PASSED"
        st.metric("Score", score1, delta=status1)

    with example_col2:
        st.markdown("**Example 2:** 5 High")
        score2 = 5 * high_score
        status2 = "❌ BLOCKED" if 5 >= block_high_count or score2 > max_score else "✅ PASSED"
        st.metric("Score", score2, delta=status2)

    with example_col3:
        st.markdown("**Example 3:** 3 Med, 5 Low")
        score3 = 3 * medium_score + 5 * low_score
        status3 = "❌ BLOCKED" if score3 > max_score else "✅ PASSED"
        st.metric("Score", score3, delta=status3)

    # Save button
    st.markdown("---")
    if st.button("💾 Save Threshold Settings", type="primary", use_container_width=True):
        st.info("⚠️ Configuration saving is disabled in dashboard mode. Edit `gate_config.yaml` directly.")

        st.code(f"""
# gate_config.yaml - Thresholds Section
gate:
  thresholds:
    block_on_critical: {block_critical}
    block_on_high_count: {block_high_count}
    block_on_medium_count: {block_medium_count}
    max_total_score: {max_score}
    critical_score: {critical_score}
    high_score: {high_score}
    medium_score: {medium_score}
    low_score: {low_score}
        """, language='yaml')


def render_scanner_settings(gate_config: Dict):
    """Render scanner configuration."""

    st.markdown("### 🔧 Scanner Configuration")

    # Bandit settings
    st.markdown("#### Bandit (SAST)")

    bandit_config = gate_config.get('bandit', {})

    col1, col2 = st.columns(2)

    with col1:
        bandit_enabled = st.checkbox(
            "Enable Bandit",
            value=bandit_config.get('enabled', True)
        )

        severity_levels = st.multiselect(
            "Severity Levels",
            options=['LOW', 'MEDIUM', 'HIGH'],
            default=bandit_config.get('severity_levels', ['LOW', 'MEDIUM', 'HIGH'])
        )

    with col2:
        confidence_levels = st.multiselect(
            "Confidence Levels",
            options=['LOW', 'MEDIUM', 'HIGH'],
            default=bandit_config.get('confidence_levels', ['LOW', 'MEDIUM', 'HIGH'])
        )

        exclude_dirs = st.text_area(
            "Exclude Directories (one per line)",
            value='\n'.join(bandit_config.get('exclude_dirs', ['.venv', 'tests', '__pycache__']))
        )

    st.markdown("---")

    # Safety settings
    st.markdown("#### Safety (SCA)")

    safety_config = gate_config.get('safety', {})

    col1, col2 = st.columns(2)

    with col1:
        safety_enabled = st.checkbox(
            "Enable Safety",
            value=safety_config.get('enabled', True)
        )

    with col2:
        req_files = st.text_area(
            "Requirements Files (one per line)",
            value='\n'.join(safety_config.get('requirements_files', ['requirements.txt']))
        )

    # View current config
    st.markdown("---")
    st.markdown("#### 📄 Current Configuration")

    if st.button("Show Current Config"):
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "gate_config.yaml"

        if config_path.exists():
            with open(config_path, 'r') as f:
                st.code(f.read(), language='yaml')


def render_path_settings():
    """Render path and directory settings."""

    st.markdown("### 📁 Path Settings")

    project_root = Path(__file__).parent.parent.parent
    reports_dir = st.session_state.get('reports_dir', project_root / "reports")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Current Paths")
        st.text_input("Project Root", value=str(project_root), disabled=True)
        st.text_input("Reports Directory", value=str(reports_dir), disabled=True)

    with col2:
        st.markdown("#### Directory Contents")

        if reports_dir.exists():
            reports = list(reports_dir.glob("*.json"))
            st.metric("JSON Reports", len(reports))

            html_reports = list(reports_dir.glob("*.html"))
            st.metric("HTML Reports", len(html_reports))
        else:
            st.warning("Reports directory does not exist")

    # Clean up old reports
    st.markdown("---")
    st.markdown("#### 🧹 Maintenance")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🗑️ Clear Old Reports (>30 days)", use_container_width=True):
            st.warning("This feature is not implemented yet")

    with col2:
        if st.button("📊 Refresh Report List", use_container_width=True):
            st.rerun()


def render_about():
    """Render about/info section."""

    st.markdown("### 📋 About DevSecOps Gate")

    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 30px; border-radius: 10px; color: white; margin-bottom: 20px;">
        <h2 style="margin: 0; color: white;">🛡️ Mini Audit Tools 2025</h2>
        <p style="margin: 10px 0 0 0; opacity: 0.9;">DevSecOps Gate - Automated Security Audit</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        #### 🎯 Features
        
        - **SAST Analysis** - Static code scanning with Bandit
        - **SCA Scanning** - Dependency checks with Safety
        - **CI/CD Integration** - GitHub Actions, GitLab CI
        - **Compliance Mapping** - OWASP, CWE, NIST
        - **Interactive Dashboard** - Real-time visualization
        - **Automated Reporting** - JSON, HTML, PDF exports
        """)

    with col2:
        st.markdown("""
        #### 🔧 Technology Stack
        
        - **Python 3.10+** - Core language
        - **Streamlit** - Dashboard framework
        - **Bandit** - SAST scanner
        - **Safety** - SCA scanner
        - **Plotly** - Visualizations
        - **GitHub Actions** - CI/CD
        """)

    st.markdown("---")

    st.markdown("""
    #### 📚 Resources
    
    | Resource | Description |
    |----------|-------------|
    | [Documentation](docs/PROJECT_PHASES.md) | Project phases and roadmap |
    | [Configuration](gate_config.yaml) | Security gate configuration |
    | [CI/CD Setup](.github/workflows/) | GitHub Actions workflows |
    | [OWASP Top 10](https://owasp.org/Top10/) | Security standard reference |
    | [CWE Database](https://cwe.mitre.org/) | Weakness enumeration |
    """)

    st.markdown("---")

    st.markdown("""
    #### 📞 Support
    
    **Project:** Capstone IT Audit - Mini Audit Tools 2025
    
    **Version:** 1.0.0
    
    For issues or feature requests, please open a GitHub issue.
    """)

    # System info
    st.markdown("---")
    with st.expander("🖥️ System Information"):
        import sys
        import platform

        st.markdown(f"""
        - **Python Version:** {sys.version.split()[0]}
        - **Platform:** {platform.system()} {platform.release()}
        - **Streamlit Version:** {st.__version__}
        """)
