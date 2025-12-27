# DevSecOps Gate 🛡️

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-SAST%20%2B%20SCA-red.svg)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-orange.svg)

**Automated Security Audit Gate for CI/CD Pipeline**

*Mini Audit Tools 2025 - Capstone Project*

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Dashboard](#-dashboard)

</div>

---

## 🎯 Overview

DevSecOps Gate adalah solusi **Automated Security Audit** yang terintegrasi dengan CI/CD Pipeline. Tool ini mengaudit keamanan kode secara otomatis dan **menghentikan deployment jika ditemukan kerentanan kritis**.

```
┌─────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline Flow                      │
├─────────────────────────────────────────────────────────────┤
│  Code Push → Bandit (SAST) → Safety (SCA) → Gate Decision  │
│                                                             │
│              ┌───────────────────┐                         │
│              │  Critical Found?  │                         │
│              └───────────────────┘                         │
│                ↙           ↘                               │
│           ❌ BLOCK        ✅ PASS                          │
│           Deployment      to Production                    │
└─────────────────────────────────────────────────────────────┘
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **SAST Scanning** | Static code analysis dengan Bandit |
| 📦 **SCA Scanning** | Dependency vulnerability check dengan Safety |
| 🚦 **Security Gate** | Automated pass/fail decision |
| 📊 **Dashboard** | Interactive Streamlit dashboard |
| 🔗 **CI/CD Integration** | GitHub Actions workflow |
| 📋 **Compliance Mapping** | OWASP, CWE, NIST standards |
| 📤 **Report Export** | JSON, HTML, CSV formats |

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- pip or pipenv

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/devsecops-gate.git
cd devsecops-gate

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Run Security Audit

```bash
# Scan your project
python scripts/run_audit.py ./src

# With custom config
python scripts/run_audit.py ./src --config gate_config.yaml

# Generate multiple report formats
python scripts/run_audit.py ./src --format json html
```

### Launch Dashboard

```bash
streamlit run dashboard/app.py
```

## 📁 Project Structure

```
devsecops-gate/
├── .github/
│   ├── workflows/
│   │   ├── security-gate.yml      # CI/CD workflow
│   │   └── scheduled-audit.yml    # Weekly scheduled audit
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── .gitlab-ci.yml                 # GitLab CI alternative
├── src/
│   ├── __init__.py
│   ├── config.py                  # Configuration management
│   ├── orchestrator.py            # Audit orchestration
│   ├── models/
│   │   ├── audit_result.py        # Data models
│   │   └── compliance.py          # CWE/OWASP mapping
│   ├── scanners/
│   │   ├── base_scanner.py        # Scanner interface
│   │   ├── bandit_scanner.py      # SAST scanner
│   │   └── safety_scanner.py      # SCA scanner
│   └── gate/
│       ├── security_gate.py       # Gate logic
│       └── severity_calculator.py
├── dashboard/
│   ├── app.py                     # Main Streamlit app
│   ├── pages/
│   │   ├── overview.py            # Executive summary
│   │   ├── report_viewer.py       # Report viewer
│   │   ├── live_scan.py           # Live scanning
│   │   ├── trends.py              # Trend analysis
│   │   ├── compliance.py          # Compliance mapping
│   │   └── settings.py            # Settings page
│   └── components/
│       ├── charts.py              # Reusable charts
│       ├── metrics.py             # Metric cards
│       ├── tables.py              # Data tables
│       └── filters.py             # Filter components
├── scripts/
│   ├── run_audit.py               # CLI entry point
│   ├── ci_runner.py               # CI-optimized runner
│   └── generate_report.py         # Report generator
├── tests/
│   ├── test_scanners.py
│   ├── test_gate.py
│   └── sample_vulnerable_code.py
├── docs/
│   └── PROJECT_PHASES.md          # Development phases
├── gate_config.yaml               # Configuration file
├── requirements.txt
├── pyproject.toml
├── CONTRIBUTING.md                # Contribution guide
└── README.md
```

## ⚙️ Configuration

Edit `gate_config.yaml` to customize gate behavior:

```yaml
gate:
  thresholds:
    block_on_critical: true      # Block on ANY critical
    block_on_high_count: 3       # Block if HIGH >= 3
    max_total_score: 25          # Block if score > 25
  
  bandit:
    enabled: true
    exclude_dirs:
      - .venv
      - tests
  
  safety:
    enabled: true
    requirements_files:
      - requirements.txt
```

## 🔗 CI/CD Integration

### GitHub Actions

Create `.github/workflows/security-gate.yml`:

```yaml
name: Security Gate

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run Security Audit
        run: python scripts/run_audit.py . --format json html
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: reports/
```

## 📊 Dashboard

The Streamlit dashboard provides:

- **Executive Summary**: High-level security metrics
- **Vulnerability Details**: Detailed findings with remediation
- **Severity Distribution**: Visual charts
- **Compliance Mapping**: OWASP, CWE references
- **Export Options**: Download reports

## 🔐 Security Standards

This tool maps findings to industry standards:

| Standard | Version | Coverage |
|----------|---------|----------|
| OWASP Top 10 | 2021 | Full mapping |
| CWE Top 25 | 2023 | Full mapping |
| NIST CSF | 2.0 | Partial |
| ISO 27001 | 2022 | Partial |

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=html

# Run specific test
pytest tests/test_gate.py -v
```

## 📖 Documentation

- [Project Phases](docs/PROJECT_PHASES.md) - Development roadmap
- [Configuration Guide](gate_config.yaml) - Configuration options

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **DevSecOps Audit Team** - *Initial work*

## 🙏 Acknowledgments

- [Bandit](https://bandit.readthedocs.io/) - Python SAST tool
- [Safety](https://pyup.io/safety/) - Dependency checker
- [Streamlit](https://streamlit.io/) - Dashboard framework
- [OWASP](https://owasp.org/) - Security standards

---

<div align="center">

**Built with ❤️ for IT Auditors**

*Mini Audit Tools 2025 - Capstone Audit TI*

</div>