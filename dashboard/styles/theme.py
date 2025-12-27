"""
Theme Configuration
===================

Centralized theme configuration for consistent styling across the dashboard.
"""

# =============================================================================
# COLOR PALETTE
# =============================================================================

# Primary brand colors
COLORS = {
    # Brand
    'primary': '#4F46E5',       # Indigo-600
    'primary_light': '#818CF8', # Indigo-400
    'primary_dark': '#3730A3',  # Indigo-800
    'secondary': '#0EA5E9',     # Sky-500
    
    # Background
    'bg_primary': '#FFFFFF',
    'bg_secondary': '#F8FAFC',  # Slate-50
    'bg_tertiary': '#F1F5F9',   # Slate-100
    'bg_dark': '#1E293B',       # Slate-800
    
    # Text
    'text_primary': '#1E293B',   # Slate-800
    'text_secondary': '#64748B', # Slate-500
    'text_muted': '#94A3B8',     # Slate-400
    'text_light': '#FFFFFF',
    
    # Borders
    'border_light': '#E2E8F0',   # Slate-200
    'border_medium': '#CBD5E1',  # Slate-300
    
    # Severity colors
    'critical': '#DC2626',  # Red-600
    'high': '#EA580C',      # Orange-600
    'medium': '#D97706',    # Amber-600
    'low': '#16A34A',       # Green-600
    'info': '#0284C7',      # Sky-600
    
    # Status colors
    'success': '#16A34A',   # Green-600
    'warning': '#D97706',   # Amber-600
    'error': '#DC2626',     # Red-600
    
    # Chart colors
    'chart_1': '#4F46E5',
    'chart_2': '#0EA5E9',
    'chart_3': '#8B5CF6',
    'chart_4': '#EC4899',
    'chart_5': '#14B8A6',
}

SEVERITY_COLORS = {
    'CRITICAL': COLORS['critical'],
    'HIGH': COLORS['high'],
    'MEDIUM': COLORS['medium'],
    'LOW': COLORS['low'],
    'INFO': COLORS['info'],
}

GATE_COLORS = {
    'PASSED': COLORS['success'],
    'WARNING': COLORS['warning'],
    'FAILED': COLORS['error'],
    'ERROR': COLORS['text_secondary'],
}


# =============================================================================
# TYPOGRAPHY
# =============================================================================

FONTS = {
    'primary': "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    'heading': "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    'mono': "'JetBrains Mono', 'Fira Code', Consolas, monospace",
}


# =============================================================================
# SPACING & SIZING
# =============================================================================

SPACING = {
    'xs': '0.25rem',
    'sm': '0.5rem',
    'md': '1rem',
    'lg': '1.5rem',
    'xl': '2rem',
    '2xl': '3rem',
}

RADIUS = {
    'sm': '4px',
    'md': '8px',
    'lg': '12px',
    'xl': '16px',
    'full': '9999px',
}

SHADOWS = {
    'sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    'md': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
    'lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
    'xl': '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
}


# =============================================================================
# MAIN CSS STYLESHEET
# =============================================================================

def get_custom_css() -> str:
    """Return the complete custom CSS stylesheet."""
    return f"""
<style>
    /* =========================================================================
       GOOGLE FONTS IMPORT
       ========================================================================= */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    /* =========================================================================
       ROOT & GLOBAL STYLES
       ========================================================================= */
    :root {{
        --primary: {COLORS['primary']};
        --primary-light: {COLORS['primary_light']};
        --primary-dark: {COLORS['primary_dark']};
        --secondary: {COLORS['secondary']};
        --bg-primary: {COLORS['bg_primary']};
        --bg-secondary: {COLORS['bg_secondary']};
        --bg-tertiary: {COLORS['bg_tertiary']};
        --text-primary: {COLORS['text_primary']};
        --text-secondary: {COLORS['text_secondary']};
        --text-muted: {COLORS['text_muted']};
        --border-light: {COLORS['border_light']};
        --border-medium: {COLORS['border_medium']};
        --success: {COLORS['success']};
        --warning: {COLORS['warning']};
        --error: {COLORS['error']};
        --critical: {COLORS['critical']};
        --high: {COLORS['high']};
        --medium: {COLORS['medium']};
        --low: {COLORS['low']};
        --info: {COLORS['info']};
    }}
    
    html, body, [class*="st-"] {{
        font-family: {FONTS['primary']};
    }}
    
    /* =========================================================================
       MAIN CONTAINER
       ========================================================================= */
    .main .block-container {{
        padding: 2rem 2.5rem;
        max-width: 1400px;
    }}
    
    @media (max-width: 768px) {{
        .main .block-container {{
            padding: 1rem 1rem;
        }}
    }}
    
    /* =========================================================================
       TYPOGRAPHY
       ========================================================================= */
    h1 {{
        font-family: {FONTS['heading']};
        font-weight: 700;
        font-size: 2rem;
        color: var(--text-primary);
        letter-spacing: -0.025em;
        margin-bottom: 0.5rem;
    }}
    
    h2 {{
        font-family: {FONTS['heading']};
        font-weight: 600;
        font-size: 1.5rem;
        color: var(--text-primary);
        letter-spacing: -0.02em;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }}
    
    h3 {{
        font-family: {FONTS['heading']};
        font-weight: 600;
        font-size: 1.125rem;
        color: var(--text-primary);
        letter-spacing: -0.01em;
        margin-top: 1rem;
        margin-bottom: 0.75rem;
    }}
    
    p, li, span {{
        font-size: 0.95rem;
        line-height: 1.6;
        color: var(--text-secondary);
    }}
    
    /* =========================================================================
       SIDEBAR
       ========================================================================= */
    [data-testid="stSidebar"] {{
        background: linear-gradient(180deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
        border-right: 1px solid var(--border-light);
    }}
    
    [data-testid="stSidebar"] [data-testid="stMarkdown"] h1 {{
        font-size: 1.5rem;
        text-align: center;
    }}
    
    [data-testid="stSidebar"] [data-testid="stMarkdown"] h3 {{
        font-size: 0.875rem;
        font-weight: 600;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 1.5rem;
    }}
    
    /* =========================================================================
       BUTTONS
       ========================================================================= */
    .stButton > button {{
        font-family: {FONTS['primary']};
        font-weight: 500;
        font-size: 0.875rem;
        border-radius: {RADIUS['md']};
        padding: 0.625rem 1.25rem;
        transition: all 0.2s ease;
        border: none;
    }}
    
    .stButton > button[kind="primary"] {{
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
        color: white;
        box-shadow: {SHADOWS['md']};
    }}
    
    .stButton > button[kind="primary"]:hover {{
        transform: translateY(-1px);
        box-shadow: {SHADOWS['lg']};
    }}
    
    .stButton > button[kind="secondary"] {{
        background: var(--bg-secondary);
        color: var(--text-primary);
        border: 1px solid var(--border-medium);
    }}
    
    .stButton > button[kind="secondary"]:hover {{
        background: var(--bg-tertiary);
        border-color: var(--primary);
    }}
    
    /* =========================================================================
       METRICS
       ========================================================================= */
    [data-testid="stMetricValue"] {{
        font-family: {FONTS['heading']};
        font-weight: 700;
        font-size: 2rem;
        color: var(--text-primary);
    }}
    
    [data-testid="stMetricLabel"] {{
        font-family: {FONTS['primary']};
        font-weight: 500;
        font-size: 0.875rem;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 0.025em;
    }}
    
    [data-testid="metric-container"] {{
        background: var(--bg-primary);
        border: 1px solid var(--border-light);
        border-radius: {RADIUS['lg']};
        padding: 1.25rem;
        box-shadow: {SHADOWS['sm']};
        transition: all 0.2s ease;
    }}
    
    [data-testid="metric-container"]:hover {{
        box-shadow: {SHADOWS['md']};
        border-color: var(--primary-light);
    }}
    
    /* =========================================================================
       CARDS & CONTAINERS
       ========================================================================= */
    .card {{
        background: var(--bg-primary);
        border: 1px solid var(--border-light);
        border-radius: {RADIUS['lg']};
        padding: 1.5rem;
        box-shadow: {SHADOWS['sm']};
        margin-bottom: 1rem;
    }}
    
    .card-header {{
        font-weight: 600;
        font-size: 1rem;
        color: var(--text-primary);
        margin-bottom: 1rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--border-light);
    }}
    
    .gradient-card {{
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
        border-radius: {RADIUS['lg']};
        padding: 1.5rem;
        color: white;
        box-shadow: {SHADOWS['lg']};
    }}
    
    .gradient-card h2, .gradient-card h3, .gradient-card p {{
        color: white;
    }}
    
    /* =========================================================================
       STATUS BANNERS
       ========================================================================= */
    .status-banner {{
        border-radius: {RADIUS['lg']};
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }}
    
    .status-passed {{
        background: linear-gradient(135deg, rgba(22, 163, 74, 0.1) 0%, rgba(22, 163, 74, 0.05) 100%);
        border: 1px solid rgba(22, 163, 74, 0.3);
        color: var(--success);
    }}
    
    .status-warning {{
        background: linear-gradient(135deg, rgba(217, 119, 6, 0.1) 0%, rgba(217, 119, 6, 0.05) 100%);
        border: 1px solid rgba(217, 119, 6, 0.3);
        color: var(--warning);
    }}
    
    .status-failed {{
        background: linear-gradient(135deg, rgba(220, 38, 38, 0.1) 0%, rgba(220, 38, 38, 0.05) 100%);
        border: 1px solid rgba(220, 38, 38, 0.3);
        color: var(--error);
    }}
    
    .status-banner .status-icon {{
        font-size: 2rem;
    }}
    
    .status-banner .status-text {{
        font-weight: 600;
        font-size: 1.125rem;
    }}
    
    .status-banner .status-reason {{
        font-size: 0.875rem;
        opacity: 0.9;
    }}
    
    /* =========================================================================
       SEVERITY BADGES
       ========================================================================= */
    .severity-badge {{
        display: inline-flex;
        align-items: center;
        padding: 0.25rem 0.75rem;
        border-radius: {RADIUS['full']};
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.025em;
    }}
    
    .severity-critical {{
        background: rgba(220, 38, 38, 0.1);
        color: var(--critical);
        border: 1px solid rgba(220, 38, 38, 0.3);
    }}
    
    .severity-high {{
        background: rgba(234, 88, 12, 0.1);
        color: var(--high);
        border: 1px solid rgba(234, 88, 12, 0.3);
    }}
    
    .severity-medium {{
        background: rgba(217, 119, 6, 0.1);
        color: var(--medium);
        border: 1px solid rgba(217, 119, 6, 0.3);
    }}
    
    .severity-low {{
        background: rgba(22, 163, 74, 0.1);
        color: var(--low);
        border: 1px solid rgba(22, 163, 74, 0.3);
    }}
    
    .severity-info {{
        background: rgba(2, 132, 199, 0.1);
        color: var(--info);
        border: 1px solid rgba(2, 132, 199, 0.3);
    }}
    
    /* =========================================================================
       TABLES
       ========================================================================= */
    .dataframe {{
        font-family: {FONTS['primary']};
        font-size: 0.875rem;
        border-collapse: collapse;
        width: 100%;
    }}
    
    .dataframe thead th {{
        background: var(--bg-tertiary);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        color: var(--text-secondary);
        padding: 0.875rem 1rem;
        border-bottom: 2px solid var(--border-medium);
    }}
    
    .dataframe tbody td {{
        padding: 0.75rem 1rem;
        border-bottom: 1px solid var(--border-light);
        color: var(--text-primary);
    }}
    
    .dataframe tbody tr:hover {{
        background: var(--bg-secondary);
    }}
    
    /* =========================================================================
       TABS
       ========================================================================= */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 0.5rem;
        background: transparent;
    }}
    
    .stTabs [data-baseweb="tab"] {{
        font-family: {FONTS['primary']};
        font-weight: 500;
        font-size: 0.875rem;
        padding: 0.75rem 1.25rem;
        border-radius: {RADIUS['md']};
        background: var(--bg-secondary);
        border: 1px solid var(--border-light);
        color: var(--text-secondary);
    }}
    
    .stTabs [data-baseweb="tab"]:hover {{
        background: var(--bg-tertiary);
        color: var(--text-primary);
    }}
    
    .stTabs [aria-selected="true"] {{
        background: var(--primary) !important;
        color: white !important;
        border-color: var(--primary) !important;
    }}
    
    /* =========================================================================
       EXPANDERS
       ========================================================================= */
    .streamlit-expanderHeader {{
        font-family: {FONTS['primary']};
        font-weight: 500;
        font-size: 0.9375rem;
        color: var(--text-primary);
        background: var(--bg-secondary);
        border-radius: {RADIUS['md']};
        padding: 0.75rem 1rem;
    }}
    
    .streamlit-expanderHeader:hover {{
        background: var(--bg-tertiary);
    }}
    
    /* =========================================================================
       INPUT FIELDS
       ========================================================================= */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > div {{
        font-family: {FONTS['primary']};
        font-size: 0.9375rem;
        border-radius: {RADIUS['md']};
        border: 1px solid var(--border-medium);
        padding: 0.625rem 0.875rem;
    }}
    
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {{
        border-color: var(--primary);
        box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
    }}
    
    /* =========================================================================
       CODE BLOCKS
       ========================================================================= */
    code {{
        font-family: {FONTS['mono']};
        font-size: 0.875rem;
        background: var(--bg-tertiary);
        padding: 0.125rem 0.375rem;
        border-radius: {RADIUS['sm']};
        color: var(--primary-dark);
    }}
    
    pre {{
        font-family: {FONTS['mono']};
        background: var(--bg-dark);
        color: var(--text-light);
        padding: 1rem;
        border-radius: {RADIUS['md']};
        overflow-x: auto;
    }}
    
    /* =========================================================================
       PROGRESS & LOADING
       ========================================================================= */
    .stProgress > div > div > div > div {{
        background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 100%);
    }}
    
    /* =========================================================================
       DIVIDERS
       ========================================================================= */
    hr {{
        border: none;
        border-top: 1px solid var(--border-light);
        margin: 1.5rem 0;
    }}
    
    /* =========================================================================
       ALERTS & MESSAGES
       ========================================================================= */
    .stAlert {{
        border-radius: {RADIUS['md']};
        border-left-width: 4px;
    }}
    
    /* =========================================================================
       SCROLLBAR
       ========================================================================= */
    ::-webkit-scrollbar {{
        width: 8px;
        height: 8px;
    }}
    
    ::-webkit-scrollbar-track {{
        background: var(--bg-secondary);
    }}
    
    ::-webkit-scrollbar-thumb {{
        background: var(--border-medium);
        border-radius: 4px;
    }}
    
    ::-webkit-scrollbar-thumb:hover {{
        background: var(--text-muted);
    }}
    
    /* =========================================================================
       RESPONSIVE ADJUSTMENTS
       ========================================================================= */
    @media (max-width: 1024px) {{
        h1 {{
            font-size: 1.75rem;
        }}
        
        h2 {{
            font-size: 1.25rem;
        }}
        
        [data-testid="stMetricValue"] {{
            font-size: 1.5rem;
        }}
    }}
    
    @media (max-width: 768px) {{
        h1 {{
            font-size: 1.5rem;
        }}
        
        h2 {{
            font-size: 1.125rem;
        }}
        
        .status-banner {{
            flex-direction: column;
            text-align: center;
        }}
        
        [data-testid="metric-container"] {{
            padding: 1rem;
        }}
    }}
    
    /* =========================================================================
       ANIMATION
       ========================================================================= */
    @keyframes fadeIn {{
        from {{ opacity: 0; transform: translateY(10px); }}
        to {{ opacity: 1; transform: translateY(0); }}
    }}
    
    .animate-fade-in {{
        animation: fadeIn 0.3s ease-out;
    }}
    
    @keyframes pulse {{
        0%, 100% {{ opacity: 1; }}
        50% {{ opacity: 0.5; }}
    }}
    
    .animate-pulse {{
        animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    }}
</style>
"""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def severity_badge(severity: str) -> str:
    """Generate HTML for a severity badge."""
    severity = severity.upper()
    return f'<span class="severity-badge severity-{severity.lower()}">{severity}</span>'


def status_banner(status: str, message: str, reason: str = "") -> str:
    """Generate HTML for a status banner."""
    icons = {
        'passed': '✅',
        'warning': '⚠️',
        'failed': '❌',
        'error': '🚫',
    }
    icon = icons.get(status.lower(), '❓')
    
    return f"""
    <div class="status-banner status-{status.lower()}">
        <span class="status-icon">{icon}</span>
        <div>
            <div class="status-text">{message}</div>
            {f'<div class="status-reason">{reason}</div>' if reason else ''}
        </div>
    </div>
    """


def card(content: str, header: str = "") -> str:
    """Generate HTML for a card container."""
    header_html = f'<div class="card-header">{header}</div>' if header else ''
    return f"""
    <div class="card">
        {header_html}
        {content}
    </div>
    """


def gradient_card(content: str) -> str:
    """Generate HTML for a gradient card."""
    return f"""
    <div class="gradient-card">
        {content}
    </div>
    """
