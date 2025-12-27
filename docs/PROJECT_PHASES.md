# 📋 Dokumentasi Fase Pengerjaan
## Mini Audit Tools 2025: DevSecOps Gate
### Automated Security Audit untuk CI/CD Pipeline

---

## 🎯 Overview Project

| Aspek | Detail |
|-------|--------|
| **Nama Project** | DevSecOps Gate - Automated Security Audit |
| **Tujuan** | Membangun security gate otomatis dalam CI/CD pipeline |
| **Bahasa** | Python 3.10+ |
| **Tools Audit** | Bandit (SAST), Safety (SCA) |
| **CI/CD Engine** | GitHub Actions |
| **Dashboard** | Streamlit |
| **Standar Acuan** | OWASP Top 10, CWE, NIST CSF, ISO 27001 |

---

## 📊 Fase Pengerjaan

```
┌─────────────────────────────────────────────────────────────────────────┐
│  FASE 1        FASE 2         FASE 3         FASE 4         FASE 5     │
│  Foundation    Core Engine    CI/CD          Dashboard      Finalisasi │
│  ────────►    ────────►      ────────►      ────────►      ────────►   │
│  [Setup]      [Audit Logic]  [Automation]   [Visualisasi]  [Delivery]  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔷 FASE 1: Foundation & Project Setup
### Durasi: 1-2 Hari

#### 1.1 Objectives
- [ ] Menyiapkan struktur folder project yang modular
- [ ] Mengkonfigurasi virtual environment Python
- [ ] Menginstall dependencies yang diperlukan
- [ ] Setup Git repository dengan best practices

#### 1.2 Deliverables

| File/Folder | Deskripsi |
|-------------|-----------|
| `requirements.txt` | Daftar dependencies Python |
| `setup.py` | Package configuration |
| `src/__init__.py` | Core module initialization |
| `scripts/` | Utility scripts |
| `.gitignore` | Git ignore rules |
| `pyproject.toml` | Modern Python project config |

#### 1.3 Struktur Folder Target
```
mini-audit-devsecops/
├── .github/
│   └── workflows/
│       └── security-gate.yml
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── bandit_scanner.py
│   │   └── safety_scanner.py
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── json_reporter.py
│   │   └── html_reporter.py
│   └── gate/
│       ├── __init__.py
│       └── security_gate.py
├── dashboard/
│   ├── app.py
│   ├── pages/
│   └── components/
├── scripts/
│   ├── run_audit.py
│   └── generate_report.py
├── tests/
│   ├── __init__.py
│   ├── test_scanners.py
│   └── sample_vulnerable_code.py
├── docs/
│   ├── PROJECT_PHASES.md
│   └── AUDIT_STANDARDS.md
├── reports/
│   └── .gitkeep
├── requirements.txt
├── setup.py
├── pyproject.toml
├── README.md
└── .gitignore
```

#### 1.4 Dependencies
```
# Core
bandit>=1.7.5
safety>=2.3.0
click>=8.1.0

# Dashboard
streamlit>=1.28.0
plotly>=5.18.0
pandas>=2.0.0

# Reporting
jinja2>=3.1.0
markdown>=3.5.0

# Development
pytest>=7.4.0
black>=23.0.0
flake8>=6.1.0
```

#### 1.5 Acceptance Criteria
- ✅ Virtual environment aktif dan semua dependencies terinstall
- ✅ Struktur folder sesuai dengan diagram
- ✅ Git repository initialized dengan .gitignore proper
- ✅ `python -c "import bandit; import safety"` berhasil

---

## 🔷 FASE 2: Core Audit Engine Development
### Durasi: 3-4 Hari

#### 2.1 Objectives
- [ ] Membangun wrapper untuk Bandit (Static Analysis)
- [ ] Membangun wrapper untuk Safety (Dependency Check)
- [ ] Membuat unified audit result format
- [ ] Implementasi severity scoring system
- [ ] Mapping ke standar industri (CWE, OWASP)

#### 2.2 Deliverables

| Komponen | File | Fungsi |
|----------|------|--------|
| Bandit Scanner | `src/scanners/bandit_scanner.py` | SAST untuk Python code |
| Safety Scanner | `src/scanners/safety_scanner.py` | Dependency vulnerability check |
| Result Model | `src/models/audit_result.py` | Unified data structure |
| Severity Engine | `src/gate/severity_calculator.py` | Risk scoring logic |
| Config Manager | `src/config.py` | Threshold & rules configuration |

#### 2.3 Arsitektur Core Engine
```
                    ┌─────────────────────┐
                    │   AuditOrchestrator │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │   Bandit    │    │   Safety    │    │  [Future]   │
    │  Scanner    │    │  Scanner    │    │  Scanners   │
    └──────┬──────┘    └──────┬──────┘    └─────────────┘
           │                  │
           └────────┬─────────┘
                    ▼
           ┌─────────────────┐
           │  AuditResult    │
           │  (Unified)      │
           └────────┬────────┘
                    ▼
           ┌─────────────────┐
           │ SecurityGate    │
           │ (Pass/Fail)     │
           └─────────────────┘
```

#### 2.4 Severity Scoring Matrix
```python
SEVERITY_SCORES = {
    "CRITICAL": 10,  # Immediate exploitation possible
    "HIGH": 8,       # Serious vulnerability
    "MEDIUM": 5,     # Moderate risk
    "LOW": 2,        # Minor issues
    "INFO": 0        # Informational only
}

# Gate Thresholds (Configurable)
GATE_THRESHOLDS = {
    "block_on_critical": True,
    "block_on_high_count": 3,
    "max_total_score": 25
}
```

#### 2.5 CWE & OWASP Mapping
| Bandit Test ID | CWE | OWASP 2024 | Severity |
|----------------|-----|------------|----------|
| B101 | CWE-259 | A07:2021 | HIGH |
| B102 | CWE-78 | A03:2021 | CRITICAL |
| B103 | CWE-732 | A01:2021 | MEDIUM |
| B104 | CWE-78 | A03:2021 | HIGH |
| B105 | CWE-259 | A07:2021 | HIGH |

#### 2.6 Acceptance Criteria
- ✅ Bandit scanner dapat scan direktori dan return hasil terstruktur
- ✅ Safety scanner dapat check requirements.txt
- ✅ Hasil dari kedua scanner terunifikasi dalam satu format
- ✅ Severity score terhitung dengan benar
- ✅ Unit tests coverage > 80%

---

## 🔷 FASE 3: CI/CD Pipeline Integration
### Durasi: 2-3 Hari

#### 3.1 Objectives
- [ ] Membuat GitHub Actions workflow
- [ ] Implementasi gate logic (pass/fail)
- [ ] Setup artifact upload untuk reports
- [ ] Konfigurasi branch protection rules
- [ ] Testing pipeline dengan berbagai skenario

#### 3.2 Deliverables

| File | Deskripsi |
|------|-----------|
| `.github/workflows/security-gate.yml` | Main CI/CD workflow |
| `.github/workflows/scheduled-audit.yml` | Scheduled security scan |
| `scripts/ci_runner.py` | CLI entry point untuk CI |
| `gate_config.yml` | Configurable gate rules |

#### 3.3 Pipeline Architecture
```yaml
┌─────────────────────────────────────────────────────────────┐
│                   GitHub Actions Workflow                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │  Trigger │ → │  Setup   │ → │  Audit   │ → │   Gate   │ │
│  │  (Push)  │   │  Python  │   │  Scans   │   │ Decision │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘ │
│                                      │              │       │
│                              ┌───────┴───────┐      │       │
│                              ▼               ▼      │       │
│                         ┌────────┐     ┌────────┐   │       │
│                         │ Bandit │     │ Safety │   │       │
│                         └────────┘     └────────┘   │       │
│                              │               │      │       │
│                              └───────┬───────┘      │       │
│                                      ▼              ▼       │
│                              ┌─────────────┐  ┌──────────┐  │
│                              │   Report    │  │ Pass/Fail│  │
│                              │  Artifact   │  │  Status  │  │
│                              └─────────────┘  └──────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### 3.4 Workflow Triggers
```yaml
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan
  workflow_dispatch:      # Manual trigger
```

#### 3.5 Gate Decision Matrix
| Condition | Action | Exit Code |
|-----------|--------|-----------|
| Critical vulnerability found | ❌ BLOCK | 1 |
| High vulnerabilities ≥ 3 | ❌ BLOCK | 1 |
| Total score > threshold | ❌ BLOCK | 1 |
| Only Medium/Low issues | ⚠️ WARN | 0 |
| No issues found | ✅ PASS | 0 |

#### 3.6 Acceptance Criteria
- ✅ Workflow trigger pada push dan PR
- ✅ Pipeline berhasil mendeteksi vulnerable code dan BLOCK
- ✅ Pipeline PASS untuk clean code
- ✅ Report artifact tersimpan dan downloadable
- ✅ Status check muncul di GitHub PR

---

## 🔷 FASE 4: Dashboard Development
### Durasi: 3-4 Hari

#### 4.1 Objectives
- [ ] Membangun Streamlit dashboard untuk IT Auditor
- [ ] Menampilkan hasil audit secara visual
- [ ] Implementasi trend analysis
- [ ] Export functionality (PDF/JSON)
- [ ] Authentication sederhana

#### 4.2 Deliverables

| File | Deskripsi |
|------|-----------|
| `dashboard/app.py` | Main Streamlit application |
| `dashboard/pages/overview.py` | Executive summary |
| `dashboard/pages/vulnerabilities.py` | Detail findings |
| `dashboard/pages/trends.py` | Historical analysis |
| `dashboard/components/charts.py` | Reusable chart components |
| `dashboard/utils/data_loader.py` | Report data parser |

#### 4.3 Dashboard Wireframe
```
┌─────────────────────────────────────────────────────────────────────┐
│  🛡️ DevSecOps Audit Dashboard                    [Export] [Refresh] │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │  CRITICAL   │ │    HIGH     │ │   MEDIUM    │ │    LOW      │   │
│  │     🔴 2    │ │    🟠 5     │ │    🟡 12    │ │    🟢 8     │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
│                                                                     │
│  ┌─────────────────────────────┐ ┌─────────────────────────────┐   │
│  │     Severity Distribution   │ │      Trend (Last 30 Days)  │   │
│  │         [PIE CHART]         │ │        [LINE CHART]         │   │
│  └─────────────────────────────┘ └─────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  📋 Vulnerability Details                                    │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │  ID    │ Severity │ File        │ Line │ CWE    │ Status    │   │
│  │  V001  │ CRITICAL │ auth.py     │ 45   │ CWE-78 │ 🔴 Open   │   │
│  │  V002  │ HIGH     │ db.py       │ 102  │ CWE-89 │ 🔴 Open   │   │
│  │  V003  │ MEDIUM   │ utils.py    │ 23   │ CWE-22 │ 🟡 Review │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  🔍 Remediation Recommendations                              │   │
│  │  ────────────────────────────────────────────────────────── │   │
│  │  V001: Replace os.system() with subprocess.run() with       │   │
│  │        shell=False to prevent command injection...          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### 4.4 Dashboard Pages

| Page | Konten | Target User |
|------|--------|-------------|
| **Overview** | Executive summary, KPI metrics, gate status | Management, Auditor |
| **Vulnerabilities** | Detailed findings table dengan filter | Security Engineer |
| **Trends** | Historical data, trend charts | IT Auditor |
| **Compliance** | Mapping ke standar (OWASP, CWE, ISO) | Compliance Officer |
| **Reports** | Export dan download reports | All Users |

#### 4.5 Key Metrics (KPI)
```python
DASHBOARD_KPIS = {
    "security_score": "0-100 score based on findings",
    "gate_pass_rate": "% of successful deployments",
    "mttr": "Mean Time to Remediate",
    "vulnerability_density": "Issues per 1000 LOC",
    "critical_exposure_days": "Days critical issues open"
}
```

#### 4.6 Acceptance Criteria
- ✅ Dashboard dapat load dan display audit reports
- ✅ Semua charts render dengan benar
- ✅ Filter dan search functionality bekerja
- ✅ Export ke PDF/JSON berhasil
- ✅ Responsive design untuk berbagai screen size

---

## 🔷 FASE 5: Finalisasi & Delivery
### Durasi: 2-3 Hari

#### 5.1 Objectives
- [ ] Code review dan refactoring
- [ ] Dokumentasi lengkap (README, API docs)
- [ ] Testing end-to-end
- [ ] Performance optimization
- [ ] Final demo preparation

#### 5.2 Deliverables

| Item | Deskripsi |
|------|-----------|
| `README.md` | Professional documentation |
| `docs/API.md` | API reference |
| `docs/USER_GUIDE.md` | User manual |
| `docs/AUDIT_REPORT_TEMPLATE.md` | Audit report template |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT License |

#### 5.3 README Structure
```markdown
# DevSecOps Gate 🛡️

## Overview
## Features  
## Quick Start
## Architecture
## Configuration
## Dashboard
## CI/CD Integration
## Audit Standards Compliance
## API Reference
## Contributing
## License
```

#### 5.4 Testing Checklist
- [ ] Unit tests semua modules
- [ ] Integration tests scanner + gate
- [ ] E2E test CI/CD pipeline
- [ ] Dashboard UI testing
- [ ] Performance benchmarking
- [ ] Security self-scan (meta-audit)

#### 5.5 Quality Gates
| Metric | Target |
|--------|--------|
| Test Coverage | ≥ 80% |
| Code Quality (Pylint) | ≥ 8.0/10 |
| Documentation | 100% public APIs |
| Zero Critical Issues | Self-scan clean |

#### 5.6 Acceptance Criteria
- ✅ README lengkap dan profesional
- ✅ Semua tests passing
- ✅ Demo berjalan lancar end-to-end
- ✅ Self-scan tidak menemukan critical issues
- ✅ Repository siap untuk submission

---

## 📅 Timeline Summary

```
Week 1                    Week 2                    Week 3
├─────────────────────────┼─────────────────────────┼──────────────┤
│ FASE 1    │   FASE 2    │   FASE 3   │   FASE 4  │   FASE 5    │
│ Foundation│ Core Engine │  CI/CD     │ Dashboard │ Finalisasi  │
│ (2 days)  │ (4 days)    │ (3 days)   │ (4 days)  │ (3 days)    │
├───────────┴─────────────┴────────────┴───────────┴─────────────┤
│                    Total: ~16 Working Days                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📎 Appendix

### A. Technology Stack
| Category | Technology |
|----------|------------|
| Language | Python 3.10+ |
| SAST Tool | Bandit 1.7+ |
| SCA Tool | Safety 2.3+ |
| CI/CD | GitHub Actions |
| Dashboard | Streamlit 1.28+ |
| Charts | Plotly 5.18+ |
| Testing | Pytest 7.4+ |

### B. Reference Standards
- OWASP Top 10:2021
- CWE Top 25:2023
- NIST Cybersecurity Framework 2.0
- ISO 27001:2022
- SANS Top 25

### C. Risk Assessment
| Risk | Mitigation |
|------|------------|
| False positives | Configurable rules + manual review |
| Performance | Incremental scanning, caching |
| Tool updates | Version pinning + regular updates |

---

## ✅ Sign-Off Checklist

| Fase | Status | Tanggal Complete | Notes |
|------|--------|------------------|-------|
| Fase 1: Foundation | ⬜ Pending | - | - |
| Fase 2: Core Engine | ⬜ Pending | - | - |
| Fase 3: CI/CD | ⬜ Pending | - | - |
| Fase 4: Dashboard | ⬜ Pending | - | - |
| Fase 5: Finalisasi | ⬜ Pending | - | - |

---

*Dokumen ini dibuat sebagai panduan pengerjaan project DevSecOps Gate untuk Capstone Audit TI 2025.*

**Last Updated:** December 27, 2025  
**Version:** 1.0
