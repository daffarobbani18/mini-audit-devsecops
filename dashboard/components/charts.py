"""
Chart Components
================

Visualization components using Plotly.
"""

import streamlit as st
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, List

# Import theme colors
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from styles.theme import SEVERITY_COLORS, GATE_COLORS, COLORS
except ImportError:
    # Fallback colors
    SEVERITY_COLORS = {
        'CRITICAL': '#DC2626',
        'HIGH': '#EA580C',
        'MEDIUM': '#D97706',
        'LOW': '#16A34A',
        'INFO': '#0284C7',
    }
    GATE_COLORS = {
        'PASSED': '#16A34A',
        'WARNING': '#D97706',
        'FAILED': '#DC2626',
        'ERROR': '#64748B',
    }
    COLORS = {
        'primary': '#4F46E5',
        'secondary': '#0EA5E9',
        'bg_secondary': '#F8FAFC',
        'text_primary': '#1E293B',
        'text_secondary': '#64748B',
    }

# Chart layout defaults
CHART_LAYOUT = {
    'font': {'family': 'Inter, sans-serif', 'color': '#1E293B'},
    'paper_bgcolor': 'rgba(0,0,0,0)',
    'plot_bgcolor': 'rgba(0,0,0,0)',
}


def render_severity_pie_chart(
    findings: Dict[str, int],
    title: str = "Vulnerability Distribution",
    height: int = 320
) -> None:
    """
    Render a pie chart showing severity distribution.
    
    Args:
        findings: Dict with keys 'critical', 'high', 'medium', 'low'
        title: Chart title
        height: Chart height in pixels
    """
    # Prepare data - only include non-zero values to avoid clutter
    all_labels = ['Critical', 'High', 'Medium', 'Low']
    all_values = [
        findings.get('critical', 0),
        findings.get('high', 0),
        findings.get('medium', 0),
        findings.get('low', 0),
    ]
    all_colors = [SEVERITY_COLORS['CRITICAL'], SEVERITY_COLORS['HIGH'],
                  SEVERITY_COLORS['MEDIUM'], SEVERITY_COLORS['LOW']]

    # Filter out zero values to make chart cleaner
    labels = []
    values = []
    colors = []
    for i, v in enumerate(all_values):
        if v > 0:
            labels.append(all_labels[i])
            values.append(v)
            colors.append(all_colors[i])

    # Skip if all zeros
    if sum(values) == 0:
        st.info("No vulnerabilities to display")
        return

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.5,
        marker=dict(
            colors=colors,
            line=dict(color='#FFFFFF', width=2)
        ),
        textinfo='percent',
        textposition='inside',
        textfont=dict(size=14, color='white', family='Inter, sans-serif'),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
        pull=[0.02] * len(values),  # Slight separation between slices
    )])

    fig.update_layout(
        title=dict(
            text=f"<b>{title}</b>",
            x=0.5,
            y=0.95,
            font=dict(size=14, family='Inter, sans-serif', color='#1E293B')
        ),
        height=height,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.05,
            xanchor="center",
            x=0.5,
            font=dict(size=12, family='Inter, sans-serif'),
            itemsizing='constant',
        ),
        margin=dict(t=50, b=80, l=30, r=30),
        **CHART_LAYOUT
    )

    # Add center annotation showing total
    total = sum(values)
    fig.add_annotation(
        text=f"<b>{total}</b><br><span style='font-size:11px'>Total</span>",
        x=0.5, y=0.5,
        font=dict(size=20, family='Inter, sans-serif', color='#1E293B'),
        showarrow=False
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
