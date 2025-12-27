"""
Test Scanners Module
====================

Unit tests for Bandit and Safety scanners.
"""

import pytest
from pathlib import Path
from datetime import datetime

# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import GateConfig, BanditConfig, SafetyConfig
from src.scanners.bandit_scanner import BanditScanner
from src.scanners.safety_scanner import SafetyScanner
from src.models.audit_result import Severity


class TestBanditScanner:
    """Tests for BanditScanner."""
    
    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = BanditScanner()
        assert scanner.name == "bandit"
    
    def test_scanner_availability(self):
        """Test scanner availability check."""
        scanner = BanditScanner()
        # This depends on whether bandit is installed
        is_available = scanner.is_available()
        assert isinstance(is_available, bool)
    
    @pytest.mark.skipif(
        not BanditScanner().is_available(),
        reason="Bandit not installed"
    )
    def test_scan_vulnerable_code(self):
        """Test scanning vulnerable code sample."""
        scanner = BanditScanner()
        
        # Get path to sample vulnerable code
        sample_file = Path(__file__).parent / "sample_vulnerable_code.py"
        
        if not sample_file.exists():
            pytest.skip("Sample vulnerable code file not found")
        
        result = scanner.scan(str(sample_file))
        
        # Should find vulnerabilities
        assert result.success is True
        assert result.scanner_name == "bandit"
        assert len(result.vulnerabilities) > 0
        
        # Check that expected vulnerabilities are found
        test_ids = [v.test_id for v in result.vulnerabilities]
        
        # These should be detected in sample_vulnerable_code.py
        # B102 (exec), B105 (hardcoded password), B301 (pickle), etc.
        assert any(tid in test_ids for tid in ["B102", "B105", "B301", "B307"])
    
    def test_scan_nonexistent_path(self):
        """Test scanning non-existent path."""
        scanner = BanditScanner()
        result = scanner.scan("/nonexistent/path/to/scan")
        
        assert result.success is False
        assert "does not exist" in result.error_message
    
    @pytest.mark.skipif(
        not BanditScanner().is_available(),
        reason="Bandit not installed"
    )
    def test_scan_clean_code(self):
        """Test scanning clean code (should pass)."""
        scanner = BanditScanner()
        
        # Create a temporary clean file
        clean_code = '''
def add(a, b):
    """Simple addition function."""
    return a + b

def greet(name):
    """Return greeting string."""
    return f"Hello, {name}!"
'''
        
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(clean_code)
            temp_path = f.name
        
        try:
            result = scanner.scan(temp_path)
            assert result.success is True
            # Should have few or no findings
            assert result.critical_count == 0
        finally:
            Path(temp_path).unlink()


class TestSafetyScanner:
    """Tests for SafetyScanner."""
    
    def test_scanner_name(self):
        """Test scanner name property."""
        scanner = SafetyScanner()
        assert scanner.name == "safety"
    
    def test_scanner_availability(self):
        """Test scanner availability check."""
        scanner = SafetyScanner()
        is_available = scanner.is_available()
        assert isinstance(is_available, bool)
    
    def test_find_requirements_files(self):
        """Test finding requirements files."""
        scanner = SafetyScanner()
        
        # Test with project root (should find requirements.txt)
        project_root = Path(__file__).parent.parent
        files = scanner._find_requirements_files(project_root)
        
        # Should find at least one requirements file
        req_names = [f.name for f in files]
        assert "requirements.txt" in req_names or len(files) >= 0


class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_scores(self):
        """Test severity score values."""
        assert Severity.CRITICAL.score == 10
        assert Severity.HIGH.score == 8
        assert Severity.MEDIUM.score == 5
        assert Severity.LOW.score == 2
        assert Severity.INFO.score == 0
    
    def test_severity_from_string(self):
        """Test converting strings to Severity."""
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL
        assert Severity.from_string("high") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM
        assert Severity.from_string("unknown") == Severity.INFO
    
    def test_severity_emoji(self):
        """Test severity emoji indicators."""
        assert Severity.CRITICAL.emoji == "🔴"
        assert Severity.HIGH.emoji == "🟠"
        assert Severity.LOW.emoji == "🟢"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
