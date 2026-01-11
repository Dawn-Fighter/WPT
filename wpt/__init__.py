"""
Web Penetration Testing Tool (WPT)

A comprehensive security scanner for web applications that performs:
- DNS enumeration and subdomain discovery
- SSL/TLS configuration analysis
- WAF detection
- API endpoint discovery
- JavaScript security analysis
- Cookie security analysis
- Form input validation testing
"""

__version__ = "2.0.0"
__author__ = "Chethas Dileep"
__license__ = "MIT"

from wpt.core.scanner import WebScanner
from wpt.utils.exceptions import WPTException, ScannerError, ConfigurationError

__all__ = ["WebScanner", "WPTException", "ScannerError", "ConfigurationError"]
