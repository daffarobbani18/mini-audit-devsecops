"""
Compliance Mapping Models
=========================

Maps vulnerabilities to industry security standards:
- OWASP Top 10 2021
- CWE Top 25 2023
- NIST Cybersecurity Framework
- ISO 27001
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ComplianceStandard(Enum):
    """Supported compliance standards."""
    
    OWASP_TOP_10_2021 = "OWASP Top 10:2021"
    CWE_TOP_25_2023 = "CWE Top 25:2023"
    NIST_CSF_2_0 = "NIST CSF 2.0"
    ISO_27001_2022 = "ISO 27001:2022"
    SANS_TOP_25 = "SANS Top 25"
    PCI_DSS_4_0 = "PCI DSS 4.0"


@dataclass
class ComplianceMapping:
    """
    Maps a vulnerability to compliance standards.
    
    Provides context for IT auditors about how a finding
    relates to industry security standards.
    """
    
    cwe_id: str
    cwe_name: str
    owasp_category: Optional[str] = None
    owasp_description: Optional[str] = None
    nist_controls: List[str] = field(default_factory=list)
    iso_controls: List[str] = field(default_factory=list)
    risk_description: str = ""
    remediation_guidance: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "owasp_description": self.owasp_description,
            "nist_controls": self.nist_controls,
            "iso_controls": self.iso_controls,
            "risk_description": self.risk_description,
            "remediation_guidance": self.remediation_guidance,
        }


# ===========================================
# CWE to OWASP Mapping Database
# ===========================================
# Reference: https://owasp.org/Top10/

CWE_OWASP_MAPPING: Dict[str, Dict] = {
    # A01:2021 - Broken Access Control
    "CWE-22": {
        "owasp": "A01:2021",
        "owasp_name": "Broken Access Control",
        "name": "Path Traversal",
        "risk": "Attackers can access files outside the intended directory",
    },
    "CWE-425": {
        "owasp": "A01:2021",
        "owasp_name": "Broken Access Control",
        "name": "Direct Request (Forced Browsing)",
        "risk": "Unauthorized access to restricted resources",
    },
    
    # A02:2021 - Cryptographic Failures
    "CWE-259": {
        "owasp": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "name": "Use of Hard-coded Password",
        "risk": "Credentials exposed in source code",
    },
    "CWE-327": {
        "owasp": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "name": "Use of Broken Crypto Algorithm",
        "risk": "Weak encryption can be broken by attackers",
    },
    "CWE-328": {
        "owasp": "A02:2021",
        "owasp_name": "Cryptographic Failures",
        "name": "Reversible One-Way Hash",
        "risk": "Hash can be reversed to expose original data",
    },
    
    # A03:2021 - Injection
    "CWE-78": {
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "name": "OS Command Injection",
        "risk": "Remote code execution through shell commands",
    },
    "CWE-79": {
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "name": "Cross-site Scripting (XSS)",
        "risk": "Malicious scripts executed in user browsers",
    },
    "CWE-89": {
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "name": "SQL Injection",
        "risk": "Database manipulation or data theft",
    },
    "CWE-94": {
        "owasp": "A03:2021",
        "owasp_name": "Injection",
        "name": "Code Injection",
        "risk": "Arbitrary code execution",
    },
    
    # A04:2021 - Insecure Design
    "CWE-209": {
        "owasp": "A04:2021",
        "owasp_name": "Insecure Design",
        "name": "Information Exposure Through Error Message",
        "risk": "Sensitive info leaked via error messages",
    },
    
    # A05:2021 - Security Misconfiguration
    "CWE-16": {
        "owasp": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "name": "Configuration",
        "risk": "Insecure default configurations",
    },
    "CWE-732": {
        "owasp": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "name": "Incorrect Permission Assignment",
        "risk": "Overly permissive access controls",
    },
    
    # A06:2021 - Vulnerable Components
    "CWE-1104": {
        "owasp": "A06:2021",
        "owasp_name": "Vulnerable and Outdated Components",
        "name": "Use of Unmaintained Third Party Components",
        "risk": "Known vulnerabilities in dependencies",
    },
    
    # A07:2021 - Auth Failures
    "CWE-287": {
        "owasp": "A07:2021",
        "owasp_name": "Identification and Authentication Failures",
        "name": "Improper Authentication",
        "risk": "Authentication bypass possible",
    },
    "CWE-798": {
        "owasp": "A07:2021",
        "owasp_name": "Identification and Authentication Failures",
        "name": "Use of Hard-coded Credentials",
        "risk": "Credentials exposed in code",
    },
    
    # A08:2021 - Software and Data Integrity
    "CWE-502": {
        "owasp": "A08:2021",
        "owasp_name": "Software and Data Integrity Failures",
        "name": "Deserialization of Untrusted Data",
        "risk": "Remote code execution via deserialization",
    },
    
    # A09:2021 - Logging Failures
    "CWE-117": {
        "owasp": "A09:2021",
        "owasp_name": "Security Logging and Monitoring Failures",
        "name": "Improper Output Neutralization for Logs",
        "risk": "Log injection attacks",
    },
    
    # A10:2021 - SSRF
    "CWE-918": {
        "owasp": "A10:2021",
        "owasp_name": "Server-Side Request Forgery (SSRF)",
        "name": "Server-Side Request Forgery",
        "risk": "Internal network access from server",
    },
}


# ===========================================
# Bandit Test ID to CWE Mapping
# ===========================================

BANDIT_CWE_MAPPING: Dict[str, str] = {
    # Assertions
    "B101": "CWE-703",  # assert_used
    
    # Exec/Eval
    "B102": "CWE-78",   # exec_used
    "B307": "CWE-78",   # eval
    
    # Hardcoded passwords/secrets
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    
    # SQL Injection
    "B608": "CWE-89",   # hardcoded_sql_expressions
    
    # Shell injection
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    
    # Crypto
    "B303": "CWE-327",  # md5/sha1
    "B304": "CWE-327",  # ciphers
    "B305": "CWE-327",  # cipher_modes
    
    # Deserialization
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    
    # YAML
    "B506": "CWE-502",  # yaml_load
    
    # SSL/TLS
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-327",  # ssl_with_bad_version
    "B503": "CWE-327",  # ssl_with_bad_defaults
    
    # Permissions
    "B103": "CWE-732",  # set_bad_file_permissions
    
    # Binding
    "B104": "CWE-200",  # hardcoded_bind_all_interfaces
    
    # Temp files
    "B108": "CWE-377",  # hardcoded_tmp_directory
    
    # Random
    "B311": "CWE-330",  # random
    
    # Requests
    "B113": "CWE-400",  # request_without_timeout
}


def get_compliance_mapping(cwe_id: str) -> Optional[ComplianceMapping]:
    """
    Get compliance mapping for a CWE ID.
    
    Args:
        cwe_id: CWE identifier (e.g., "CWE-78")
        
    Returns:
        ComplianceMapping with OWASP and other standard mappings
    """
    if cwe_id not in CWE_OWASP_MAPPING:
        return None
    
    mapping_data = CWE_OWASP_MAPPING[cwe_id]
    
    return ComplianceMapping(
        cwe_id=cwe_id,
        cwe_name=mapping_data["name"],
        owasp_category=mapping_data["owasp"],
        owasp_description=mapping_data["owasp_name"],
        risk_description=mapping_data["risk"],
    )


def get_cwe_from_bandit_test(test_id: str) -> Optional[str]:
    """
    Get CWE ID from Bandit test ID.
    
    Args:
        test_id: Bandit test identifier (e.g., "B102")
        
    Returns:
        CWE ID string or None
    """
    return BANDIT_CWE_MAPPING.get(test_id)
