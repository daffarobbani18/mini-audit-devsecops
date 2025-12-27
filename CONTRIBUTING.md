# Contributing to DevSecOps Gate

Thank you for your interest in contributing to Mini Audit Tools 2025!

## 🚀 Getting Started

1. **Fork the repository**
2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/mini-audit-devsecops.git
   cd mini-audit-devsecops
   ```

3. **Set up development environment:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   ```

4. **Run tests to verify setup:**
   ```bash
   pytest tests/ -v
   ```

## 📝 Development Workflow

### Branch Naming
- `feature/` - New features (e.g., `feature/add-semgrep-scanner`)
- `fix/` - Bug fixes (e.g., `fix/bandit-path-issue`)
- `docs/` - Documentation (e.g., `docs/update-readme`)
- `refactor/` - Code refactoring

### Commit Messages
Follow conventional commits:
```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(scanner): add Semgrep integration
fix(dashboard): resolve chart rendering issue
docs(readme): update installation instructions
```

### Pull Request Process

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes and commit:**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   ```

3. **Run tests and linting:**
   ```bash
   pytest tests/ -v
   black src/ tests/ scripts/ dashboard/
   flake8 src/ tests/
   ```

4. **Push and create PR:**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Fill out the PR template** with:
   - Description of changes
   - Type of change
   - Testing performed
   - Security checklist

## 🧪 Testing

### Running Tests
```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=html

# Specific test file
pytest tests/test_scanners.py -v
```

### Writing Tests
- Place tests in `tests/` directory
- Name test files as `test_*.py`
- Name test functions as `test_*`
- Use fixtures for common setup

Example:
```python
import pytest
from src.scanners.bandit_scanner import BanditScanner

def test_bandit_scanner_initialization():
    scanner = BanditScanner()
    assert scanner.name == "bandit"

def test_bandit_scan_vulnerable_code(tmp_path):
    # Create test file
    test_file = tmp_path / "vulnerable.py"
    test_file.write_text("password = 'hardcoded123'")
    
    scanner = BanditScanner()
    result = scanner.scan(str(tmp_path))
    
    assert len(result.vulnerabilities) > 0
```

## 📁 Project Structure

```
mini-audit-devsecops/
├── src/                    # Core library
│   ├── config.py          # Configuration management
│   ├── orchestrator.py    # Audit orchestration
│   ├── models/            # Data models
│   ├── scanners/          # Scanner implementations
│   └── gate/              # Security gate logic
├── scripts/               # CLI tools
├── dashboard/             # Streamlit dashboard
│   ├── app.py            # Main app
│   ├── pages/            # Dashboard pages
│   └── components/       # UI components
├── tests/                 # Test suite
├── docs/                  # Documentation
└── .github/               # GitHub workflows
```

## 🔒 Security Guidelines

- **Never commit secrets** - Use environment variables
- **Run security scans** before submitting PR
- **Review dependencies** for known vulnerabilities
- **Follow secure coding practices**

## 📚 Code Style

We use:
- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run before committing:
```bash
black src/ tests/ scripts/ dashboard/
isort src/ tests/ scripts/ dashboard/
flake8 src/ tests/
mypy src/
```

## 🐛 Reporting Bugs

1. **Check existing issues** first
2. **Use the bug report template**
3. **Include:**
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details
   - Error logs

## 💡 Feature Requests

1. **Check existing issues** for similar requests
2. **Use the feature request template**
3. **Describe:**
   - The problem you're solving
   - Your proposed solution
   - Alternative approaches considered

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Thank You!

Your contributions make this project better for everyone!
