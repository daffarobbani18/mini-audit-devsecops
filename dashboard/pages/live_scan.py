"""
Live Scan Page
==============

Run security scans directly from the dashboard.
"""

import streamlit as st
import subprocess
import json
import sys
import os
from pathlib import Path
from datetime import datetime
import threading
import time

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def get_python_executable() -> str:
    """Get the Python executable path."""
    # Try to find the venv Python
    project_root = Path(__file__).parent.parent.parent
    
    if os.name == 'nt':  # Windows
        venv_python = project_root / ".venv" / "Scripts" / "python.exe"
    else:  # Unix
        venv_python = project_root / ".venv" / "bin" / "python"
    
    if venv_python.exists():
        return str(venv_python)
    
    return sys.executable


def run_audit(target_path: str, output_dir: str) -> dict:
    """
    Run the security audit.
    
    Returns:
        Dict with 'success', 'output', 'error', and 'report_path' keys
    """
    project_root = Path(__file__).parent.parent.parent
    script_path = project_root / "scripts" / "ci_runner.py"
    python_exe = get_python_executable()
    
    cmd = [
        python_exe,
        str(script_path),
        "--target", target_path,
        "--output", output_dir,
        "--format", "json",
        "--ci-mode"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            cwd=str(project_root)
        )
        
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr,
            'return_code': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'output': '',
            'error': 'Scan timed out after 5 minutes',
            'return_code': -1
        }
    except Exception as e:
        return {
            'success': False,
            'output': '',
            'error': str(e),
            'return_code': -1
        }


def render():
    """Render the live scan page."""
    
    st.title("🔍 Live Security Scan")
    st.markdown("Run security scans directly from the dashboard")
    st.markdown("---")
    
    # Initialize session state
    if 'scan_running' not in st.session_state:
        st.session_state.scan_running = False
    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    
    project_root = Path(__file__).parent.parent.parent
    
    # Scan Configuration
    st.markdown("### ⚙️ Scan Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Target path
        target_path = st.text_input(
            "Target Path",
            value=".",
            help="Path to scan (relative to project root)"
        )
        
        # Validate path
        full_target = project_root / target_path
        if full_target.exists():
            st.success(f"✅ Path exists: `{full_target}`")
        else:
            st.error(f"❌ Path not found: `{full_target}`")
    
    with col2:
        # Output directory
        output_dir = st.text_input(
            "Output Directory",
            value="reports",
            help="Directory for scan reports"
        )
        
        # Quick presets
        st.markdown("**Quick Presets:**")
        preset_col1, preset_col2 = st.columns(2)
        
        with preset_col1:
            if st.button("📁 Scan `src/`", use_container_width=True):
                st.session_state.scan_target = "src"
                st.rerun()
        
        with preset_col2:
            if st.button("📁 Scan All", use_container_width=True):
                st.session_state.scan_target = "."
                st.rerun()
    
    # Use preset if set
    if 'scan_target' in st.session_state:
        target_path = st.session_state.scan_target
        del st.session_state.scan_target
    
    st.markdown("---")
    
    # Scan Options
    with st.expander("🔧 Advanced Options", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Scanners**")
            run_bandit = st.checkbox("Bandit (SAST)", value=True, help="Static code analysis")
            run_safety = st.checkbox("Safety (SCA)", value=True, help="Dependency scanning")
        
        with col2:
            st.markdown("**Output**")
            output_json = st.checkbox("JSON Report", value=True)
            output_html = st.checkbox("HTML Report", value=True)
    
    st.markdown("---")
    
    # Run Scan Button
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        if st.button(
            "🚀 Start Security Scan",
            type="primary",
            use_container_width=True,
            disabled=st.session_state.scan_running or not full_target.exists()
        ):
            st.session_state.scan_running = True
            st.session_state.scan_result = None
            
            # Run the scan
            with st.spinner("🔍 Running security scan..."):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Simulate progress while running
                status_text.text("Initializing scanners...")
                progress_bar.progress(10)
                
                status_text.text("Running Bandit (SAST)...")
                progress_bar.progress(30)
                
                # Actually run the audit
                result = run_audit(
                    target_path=target_path,
                    output_dir=str(project_root / output_dir)
                )
                
                status_text.text("Running Safety (SCA)...")
                progress_bar.progress(60)
                
                status_text.text("Generating reports...")
                progress_bar.progress(80)
                
                status_text.text("Finalizing...")
                progress_bar.progress(100)
                
                st.session_state.scan_result = result
                st.session_state.scan_running = False
                
                time.sleep(0.5)
                status_text.empty()
                progress_bar.empty()
            
            st.rerun()
    
    # Display Results
    if st.session_state.scan_result:
        result = st.session_state.scan_result
        
        st.markdown("---")
        st.markdown("### 📊 Scan Results")
        
        if result['success']:
            st.success("✅ **Security scan completed successfully!**")
        else:
            if result['return_code'] == 1:
                st.warning("⚠️ **Scan completed - Security issues found!**")
            else:
                st.error("❌ **Scan failed with errors**")
        
        # Show output
        with st.expander("📝 Scan Output", expanded=True):
            if result['output']:
                st.code(result['output'], language='text')
            if result['error'] and result['return_code'] != 1:
                st.error(result['error'])
        
        # Load and display the report
        reports_dir = project_root / output_dir
        summary_file = reports_dir / "audit_summary.json"
        
        if summary_file.exists():
            try:
                with open(summary_file, 'r') as f:
                    summary = json.load(f)
                
                st.markdown("---")
                st.markdown("### 📋 Quick Summary")
                
                # Gate decision
                decision = summary.get('gate_decision', 'UNKNOWN')
                if decision == 'PASSED':
                    st.success(f"✅ **Gate Decision: {decision}**")
                elif decision == 'WARNING':
                    st.warning(f"⚠️ **Gate Decision: {decision}**")
                else:
                    st.error(f"❌ **Gate Decision: {decision}**")
                
                # Metrics
                findings = summary.get('findings', {})
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    st.metric("🔴 Critical", findings.get('critical', 0))
                with col2:
                    st.metric("🟠 High", findings.get('high', 0))
                with col3:
                    st.metric("🟡 Medium", findings.get('medium', 0))
                with col4:
                    st.metric("🟢 Low", findings.get('low', 0))
                with col5:
                    st.metric("📊 Score", summary.get('total_score', 0))
                
                # Actions
                st.markdown("---")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📋 View Full Report", use_container_width=True):
                        st.session_state.current_page = 'report_viewer'
                        st.rerun()
                
                with col2:
                    st.download_button(
                        label="📥 Download Summary",
                        data=json.dumps(summary, indent=2),
                        file_name=f"scan_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                
                with col3:
                    if st.button("🔄 Run Another Scan", use_container_width=True):
                        st.session_state.scan_result = None
                        st.rerun()
                
            except Exception as e:
                st.error(f"Error reading summary: {e}")
        
        # Clear result button
        if st.button("🗑️ Clear Results"):
            st.session_state.scan_result = None
            st.rerun()
    
    # Help section
    st.markdown("---")
    with st.expander("ℹ️ Help & Tips"):
        st.markdown("""
        ### What gets scanned?
        
        **Bandit (SAST - Static Application Security Testing)**
        - Python source code analysis
        - Detects common security issues like:
          - Hardcoded passwords
          - SQL injection vulnerabilities
          - Insecure random number generation
          - Shell injection risks
        
        **Safety (SCA - Software Composition Analysis)**
        - Checks dependencies in `requirements.txt`
        - Identifies known vulnerabilities in packages
        - References CVE database
        
        ### Tips
        
        1. **Scan specific directories** to focus on your code (e.g., `src/`)
        2. **Exclude test directories** in `gate_config.yaml`
        3. **Run before committing** to catch issues early
        4. **Review findings** and prioritize Critical/High severity
        """)
