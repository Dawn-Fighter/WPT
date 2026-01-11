"""Scanner modules for WPT."""

from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.modules.security_headers_scanner import SecurityHeadersScanner

__all__ = ["BaseModule", "Finding", "Severity", "SecurityHeadersScanner"]
