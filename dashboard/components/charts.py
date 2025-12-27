"""
Chart Components
================

Visualization components using Plotly.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, List, Optional


# Color schemes
SEVERITY_COLORS = {
    'CRITICAL': '#dc3545',
    'HIGH': '#fd7e14',
    'MEDIUM': '#ffc107',
    'LOW': '#28a745',
    'INFO': '#17a2b8',
}

GATE_COLORS = {
    'PASSED': '#28a745',
    'WARNING': '#ffc107',
    'FAILED': '#dc3545',
    'ERROR': '#6c757d',
}


def render_severity_pie_chart(
    findings: Dict[str, int],
    title: str = "Vulnerability Distribution",
    height: int = 300
) -> None:
    """
    Render a pie chart showing severity distribution.
    
    Args:
        findings: Dict with keys 'critical', 'high', 'medium', 'low'
        title: Chart title
        height: Chart height in pixels
    """
    # Prepare data
    labels = ['Critical', 'High', 'Medium', 'Low']
    values = [
        findings.get('critical', 0),
        findings.get('high', 0),
        findings.get('medium', 0),
        findings.get('low', 0),
    ]
    colors = [SEVERITY_COLORS['CRITICAL'], SEVERITY_COLORS['HIGH'], 
              SEVERITY_COLORS['MEDIUM'], SEVERITY_COLORS['LOW']]
    
    # Skip if all zeros
    if sum(values) == 0:
        st.info("No vulnerabilities to display")
        return
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker_colors=colors,
        textinfo='label+value',
        textposition='outside',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )])
    
    fig.update_layout(
        title=dict(text=title, x=0.5, font=dict(size=16)),
        height=height,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        margin=dict(t=50, b=50, l=20, r=20),
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_severity_bar_chart(
    findings: Dict[str, int],
    title: str = "Findings by Severity",
    height: int = 300,
    horizontal: bool = False
) -> None:
    """
    Render a bar chart showing severity counts.
    
    Args:
        findings: Dict with severity counts
        title: Chart title
        height: Chart height
        horizontal: If True, render horizontal bars
    """
    df = pd.DataFrame({
        'Severity': ['Critical', 'High', 'Medium', 'Low'],
        'Count': [
            findings.get('critical', 0),
            findings.get('high', 0),
            findings.get('medium', 0),
            findings.get('low', 0),
        ],
        'Color': [SEVERITY_COLORS['CRITICAL'], SEVERITY_COLORS['HIGH'],
                  SEVERITY_COLORS['MEDIUM'], SEVERITY_COLORS['LOW']]
    })
    
    if horizontal:
        fig = go.Figure(go.Bar(
            x=df['Count'],
            y=df['Severity'],
            orientation='h',
            marker_color=df['Color'],
            text=df['Count'],
            textposition='outside',
        ))
    else:
        fig = go.Figure(go.Bar(
            x=df['Severity'],
            y=df['Count'],
            marker_color=df['Color'],
            text=df['Count'],
            textposition='outside',
        ))
    
    fig.update_layout(
        title=dict(text=title, x=0.5, font=dict(size=16)),
        height=height,
        showlegend=False,
        margin=dict(t=50, b=30, l=30, r=30),
        xaxis_title=None,
        yaxis_title=None,
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_trend_line_chart(
    data: List[Dict],
    title: str = "Security Trend Over Time",
    height: int = 400
) -> None:
    """
    Render a line chart showing trends over time.
    
    Args:
        data: List of audit results with timestamps
        title: Chart title
        height: Chart height
    """
    if not data:
        st.info("No historical data available")
        return
    
    # Prepare data
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Total Vulnerabilities', 'Risk Score'),
        vertical_spacing=0.15,
        row_heights=[0.5, 0.5]
    )
    
    # Total vulnerabilities line
    fig.add_trace(
        go.Scatter(
            x=df['timestamp'],
            y=df['total'],
            mode='lines+markers',
            name='Total Findings',
            line=dict(color='#667eea', width=2),
            marker=dict(size=8),
            hovertemplate='%{x}<br>Findings: %{y}<extra></extra>'
        ),
        row=1, col=1
    )
    
    # Risk score line
    fig.add_trace(
        go.Scatter(
            x=df['timestamp'],
            y=df['score'],
            mode='lines+markers',
            name='Risk Score',
            line=dict(color='#764ba2', width=2),
            marker=dict(size=8),
            fill='tozeroy',
            fillcolor='rgba(118, 75, 162, 0.1)',
            hovertemplate='%{x}<br>Score: %{y}<extra></extra>'
        ),
        row=2, col=1
    )
    
    fig.update_layout(
        title=dict(text=title, x=0.5, font=dict(size=16)),
        height=height,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        margin=dict(t=80, b=30, l=50, r=30),
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_scanner_comparison(
    scan_results: List[Dict],
    title: str = "Scanner Results Comparison",
    height: int = 300
) -> None:
    """
    Render a comparison chart between different scanners.
    
    Args:
        scan_results: List of scan results from different scanners
        title: Chart title
        height: Chart height
    """
    if not scan_results:
        st.info("No scanner results to compare")
        return
    
    scanners = []
    counts = []
    
    for result in scan_results:
        scanner_name = result.get('scanner_name', 'Unknown')
        vuln_count = len(result.get('vulnerabilities', []))
        scanners.append(scanner_name.capitalize())
        counts.append(vuln_count)
    
    colors = ['#667eea', '#764ba2', '#f093fb', '#f5576c']
    
    fig = go.Figure(go.Bar(
        x=scanners,
        y=counts,
        marker_color=colors[:len(scanners)],
        text=counts,
        textposition='outside',
    ))
    
    fig.update_layout(
        title=dict(text=title, x=0.5, font=dict(size=16)),
        height=height,
        showlegend=False,
        margin=dict(t=50, b=30, l=30, r=30),
        xaxis_title="Scanner",
        yaxis_title="Findings",
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_compliance_radar(
    compliance_scores: Dict[str, float],
    title: str = "Compliance Coverage",
    height: int = 400
) -> None:
    """
    Render a radar chart showing compliance coverage.
    
    Args:
        compliance_scores: Dict mapping framework names to scores (0-100)
        title: Chart title
        height: Chart height
    """
    if not compliance_scores:
        st.info("No compliance data available")
        return
    
    categories = list(compliance_scores.keys())
    values = list(compliance_scores.values())
    
    # Close the radar chart
    categories.append(categories[0])
    values.append(values[0])
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        fillcolor='rgba(102, 126, 234, 0.3)',
        line=dict(color='#667eea', width=2),
        marker=dict(size=8, color='#667eea'),
        name='Coverage'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 100],
                ticksuffix='%'
            )
        ),
        title=dict(text=title, x=0.5, font=dict(size=16)),
        height=height,
        showlegend=False,
        margin=dict(t=80, b=30, l=80, r=80),
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_heatmap(
    data: pd.DataFrame,
    title: str = "Vulnerability Heatmap",
    height: int = 400
) -> None:
    """
    Render a heatmap (e.g., files vs severity).
    
    Args:
        data: DataFrame with rows as files, columns as severity
        title: Chart title
        height: Chart height
    """
    if data.empty:
        st.info("No data for heatmap")
        return
    
    fig = go.Figure(data=go.Heatmap(
        z=data.values,
        x=data.columns,
        y=data.index,
        colorscale=[
            [0, '#f8f9fa'],
            [0.25, '#ffc107'],
            [0.5, '#fd7e14'],
            [0.75, '#dc3545'],
            [1, '#721c24']
        ],
        hovertemplate='File: %{y}<br>Severity: %{x}<br>Count: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title=dict(text=title, x=0.5, font=dict(size=16)),
        height=height,
        margin=dict(t=50, b=30, l=150, r=30),
        xaxis_title="Severity",
        yaxis_title="File",
    )
    
    st.plotly_chart(fig, use_container_width=True)
