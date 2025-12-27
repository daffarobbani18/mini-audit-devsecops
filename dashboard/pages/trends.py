"""
Trends Page
===========

Historical analysis of security posture over time.
"""

import streamlit as st
import json
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from dashboard.components.charts import render_trend_line_chart


def load_all_reports(reports_dir: Path, limit: int = 50) -> List[Dict]:
    """Load all audit reports for trend analysis."""
    if not reports_dir.exists():
        return []
    
    reports = sorted(reports_dir.glob("audit_report_*.json"), reverse=True)[:limit]
    loaded = []
    
    for report_path in reports:
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Add filename for reference
                data['_filename'] = report_path.name
                loaded.append(data)
        except Exception as e:
            continue
    
    return loaded


def prepare_trend_data(reports: List[Dict]) -> pd.DataFrame:
    """Prepare data for trend analysis."""
    if not reports:
        return pd.DataFrame()
    
    data = []
    for report in reports:
        summary = report.get('summary', {})
        findings = summary.get('findings', {})
        
        timestamp = report.get('audit_timestamp', '')
        try:
            if isinstance(timestamp, str):
                ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                ts = timestamp
        except:
            continue
        
        data.append({
            'timestamp': ts,
            'audit_id': report.get('audit_id', 'N/A'),
            'gate_decision': report.get('gate_decision', 'UNKNOWN'),
            'total_score': report.get('total_score', 0),
            'critical': findings.get('critical', 0),
            'high': findings.get('high', 0),
            'medium': findings.get('medium', 0),
            'low': findings.get('low', 0),
            'total': findings.get('total', sum([
                findings.get('critical', 0),
                findings.get('high', 0),
                findings.get('medium', 0),
                findings.get('low', 0),
            ])),
        })
    
    df = pd.DataFrame(data)
    if not df.empty:
        df = df.sort_values('timestamp')
    
    return df


def render():
    """Render the trends page."""
    
    st.title("📈 Security Trends")
    st.markdown("Track your security posture over time")
    st.markdown("---")
    
    # Load reports
    reports_dir = st.session_state.get('reports_dir', Path(__file__).parent.parent.parent / "reports")
    reports = load_all_reports(reports_dir)
    
    if not reports:
        st.warning("📊 No historical data available yet.")
        st.info("Run multiple security scans to see trends over time.")
        
        if st.button("🔍 Run a Scan Now", type="primary"):
            st.session_state.current_page = 'live_scan'
            st.rerun()
        return
    
    # Prepare trend data
    df = prepare_trend_data(reports)
    
    if df.empty:
        st.warning("Could not parse report data for trend analysis.")
        return
    
    # Summary stats
    st.markdown("### 📊 Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Scans",
            len(df),
            help="Total number of audit scans"
        )
    
    with col2:
        passed = len(df[df['gate_decision'] == 'PASSED'])
        pass_rate = (passed / len(df)) * 100 if len(df) > 0 else 0
        st.metric(
            "Pass Rate",
            f"{pass_rate:.1f}%",
            help="Percentage of scans that passed"
        )
    
    with col3:
        avg_score = df['total_score'].mean()
        st.metric(
            "Avg Risk Score",
            f"{avg_score:.1f}",
            help="Average risk score across all scans"
        )
    
    with col4:
        latest_score = df.iloc[-1]['total_score'] if len(df) > 0 else 0
        prev_score = df.iloc[-2]['total_score'] if len(df) > 1 else latest_score
        delta = latest_score - prev_score
        st.metric(
            "Latest Score",
            latest_score,
            delta=f"{delta:+.0f}" if delta != 0 else None,
            delta_color="inverse"  # Lower is better
        )
    
    st.markdown("---")
    
    # Date range filter
    col1, col2 = st.columns([3, 1])
    
    with col2:
        date_range = st.selectbox(
            "Time Range",
            options=['All Time', 'Last 7 Days', 'Last 30 Days', 'Last 90 Days'],
            index=0
        )
    
    # Filter by date
    if date_range != 'All Time':
        days = {'Last 7 Days': 7, 'Last 30 Days': 30, 'Last 90 Days': 90}[date_range]
        cutoff = datetime.now() - timedelta(days=days)
        df = df[df['timestamp'] >= cutoff]
    
    if df.empty:
        st.info(f"No data available for {date_range}")
        return
    
    # Main trend chart
    st.markdown("### 📉 Vulnerability Trend")
    
    # Prepare data for trend chart
    trend_data = df[['timestamp', 'total', 'total_score']].copy()
    trend_data = trend_data.rename(columns={'total': 'total', 'total_score': 'score'})
    render_trend_line_chart(trend_data.to_dict('records'))
    
    st.markdown("---")
    
    # Detailed charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎯 Severity Breakdown Over Time")
        
        # Stacked area chart
        import plotly.graph_objects as go
        
        fig = go.Figure()
        
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        for severity in ['low', 'medium', 'high', 'critical']:
            fig.add_trace(go.Scatter(
                x=df['timestamp'],
                y=df[severity],
                name=severity.capitalize(),
                stackgroup='one',
                line=dict(color=colors[severity]),
                hovertemplate=f'{severity.capitalize()}: %{{y}}<extra></extra>'
            ))
        
        fig.update_layout(
            height=350,
            margin=dict(t=30, b=30, l=30, r=30),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            xaxis_title=None,
            yaxis_title="Count"
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 🚦 Gate Decision History")
        
        # Gate decision pie chart
        import plotly.express as px
        
        decision_counts = df['gate_decision'].value_counts()
        
        fig = px.pie(
            values=decision_counts.values,
            names=decision_counts.index,
            color=decision_counts.index,
            color_discrete_map={
                'PASSED': '#28a745',
                'WARNING': '#ffc107',
                'FAILED': '#dc3545',
                'ERROR': '#6c757d'
            },
            hole=0.4
        )
        
        fig.update_layout(
            height=350,
            margin=dict(t=30, b=30, l=30, r=30),
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Recent scans table
    st.markdown("### 📋 Recent Scans")
    
    recent_df = df.tail(10).copy()
    recent_df = recent_df.sort_values('timestamp', ascending=False)
    
    # Format for display
    display_df = recent_df[['timestamp', 'audit_id', 'gate_decision', 'total_score', 'critical', 'high', 'medium', 'low']].copy()
    display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
    display_df.columns = ['Timestamp', 'Audit ID', 'Decision', 'Score', '🔴 Crit', '🟠 High', '🟡 Med', '🟢 Low']
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            'Decision': st.column_config.TextColumn(
                'Decision',
                help="Gate decision",
                width='small'
            ),
            'Score': st.column_config.ProgressColumn(
                'Score',
                help="Risk score",
                min_value=0,
                max_value=100,
                format='%d'
            )
        }
    )
    
    # Export trend data
    st.markdown("---")
    st.markdown("### 📤 Export Trend Data")
    
    col1, col2 = st.columns(2)
    
    with col1:
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"security_trends_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    
    with col2:
        json_data = df.to_json(orient='records', date_format='iso')
        st.download_button(
            label="📥 Download JSON",
            data=json_data,
            file_name=f"security_trends_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )
