"""Security Headers Scanner Module - checks HTTP security headers."""

from typing import List
from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.utils.constants import SECURITY_HEADERS


class SecurityHeadersScanner(BaseModule):
    """Scanner for analyzing HTTP security headers."""

    HEADER_RECOMMENDATIONS = {
        "Strict-Transport-Security": "Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "X-Frame-Options": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
        "X-Content-Type-Options": "Add X-Content-Type-Options: nosniff to prevent MIME sniffing",
        "Content-Security-Policy": "Add CSP to prevent XSS: Content-Security-Policy: default-src 'self'",
        "X-XSS-Protection": "Add X-XSS-Protection: 1; mode=block (legacy but useful)",
        "Referrer-Policy": "Add Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy": "Add Permissions-Policy to control browser features",
    }

    def scan(self) -> List[Finding]:
        """Scan target for security headers."""
        self.logger.info("Starting security headers analysis")

        try:
            response = self.session.get(
                self.target_url, timeout=self.timeout, allow_redirects=True
            )
            headers = response.headers

            # Check for missing security headers
            for header in SECURITY_HEADERS:
                if header not in headers:
                    severity = (
                        Severity.HIGH
                        if header
                        in [
                            "Strict-Transport-Security",
                            "X-Frame-Options",
                            "Content-Security-Policy",
                        ]
                        else Severity.MEDIUM
                    )
                    self.add_finding(
                        category="Missing Security Header",
                        description=f"{header} header missing",
                        severity=severity,
                        recommendation=self.HEADER_RECOMMENDATIONS.get(
                            header, f"Add {header} header"
                        ),
                        missing_header=header,
                    )
                else:
                    # Header present - analyze its value
                    value = headers[header]
                    self.add_finding(
                        category="Security Header Present",
                        description=f"{header}: {value[:100]}",
                        severity=Severity.INFO,
                        recommendation="Review configuration for best practices",
                        header=header,
                        value=value,
                    )

            # Check for information disclosure headers
            info_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in info_headers:
                if header in headers:
                    self.add_finding(
                        category="Information Disclosure",
                        description=f"{header} header reveals server information: {headers[header]}",
                        severity=Severity.LOW,
                        recommendation=f"Remove or obfuscate {header} header",
                        header=header,
                        value=headers[header],
                    )

        except Exception as e:
            self.logger.error(f"Error checking security headers: {e}")
            self.add_finding(
                category="Security Headers Error",
                description=f"Failed to check security headers: {str(e)}",
                severity=Severity.LOW,
            )

        self.logger.info(
            f"Security headers analysis completed with {len(self.findings)} findings"
        )
        return self.findings
