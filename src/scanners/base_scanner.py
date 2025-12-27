"""
Base Scanner Interface
======================

Abstract base class defining the scanner interface.
All scanner implementations must inherit from this class.
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.config import GateConfig
from src.models.audit_result import ScanResult


class BaseScanner(ABC):
    """
    Abstract base class for security scanners.
    
    All scanner implementations (Bandit, Safety, etc.) must
    inherit from this class and implement the scan() method.
    
    Example:
        class CustomScanner(BaseScanner):
            @property
            def name(self) -> str:
                return "custom-scanner"
            
            def scan(self, target_path: str) -> ScanResult:
                # Implementation
                pass
    """

    def __init__(self, config: Optional[GateConfig] = None):
        """
        Initialize scanner with optional configuration.
        
        Args:
            config: GateConfig instance with scanner settings
        """
        self.config = config or GateConfig()

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the scanner name.
        
        Returns:
            String identifier for this scanner
        """
        pass

    @property
    def version(self) -> str:
        """
        Return the scanner version.
        
        Override this to report actual tool version.
        
        Returns:
            Version string
        """
        return "unknown"

    @abstractmethod
    def scan(self, target_path: str) -> ScanResult:
        """
        Execute security scan on target path.
        
        Args:
            target_path: Path to file or directory to scan
            
        Returns:
            ScanResult containing findings and metadata
        """
        pass

    def is_available(self) -> bool:
        """
        Check if the scanner tool is available.
        
        Override to implement availability check for external tools.
        
        Returns:
            True if scanner can be used
        """
        return True

    def get_config_summary(self) -> dict:
        """
        Return summary of current scanner configuration.
        
        Returns:
            Dictionary with configuration details
        """
        return {
            "scanner": self.name,
            "version": self.version,
            "available": self.is_available(),
        }
