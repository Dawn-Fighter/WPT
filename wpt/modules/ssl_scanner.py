"""SSL/TLS configuration analysis module."""

from typing import List
import socket
import ssl
from datetime import datetime
from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.utils.constants import SSL_PORT, RECOMMENDED_TLS_VERSION, WEAK_CIPHERS


class SSLScanner(BaseModule):
    """
    Analyzes SSL/TLS configuration.

    Checks:
        - HTTPS usage
        - Certificate expiration
        - TLS version
        - Cipher suite strength
    """

    def scan(self) -> List[Finding]:
        """
        Perform SSL/TLS analysis.

        Returns:
            List of findings from SSL/TLS analysis
        """
        self.logger.info(f"Starting SSL/TLS analysis for {self.domain}")

        # Check if site uses HTTPS
        if not self.target_url.startswith("https"):
            self.add_finding(
                category="SSL/TLS",
                description="Site does not use HTTPS",
                severity=Severity.HIGH,
                recommendation="Enable HTTPS and redirect all HTTP traffic to HTTPS",
            )
            self.logger.warning("Site does not use HTTPS")
            return self.findings

        try:
            self._analyze_certificate()
        except socket.gaierror as e:
            self.logger.error(f"DNS resolution error: {e}")
            self.add_finding(
                category="SSL/TLS Error",
                description=f"Unable to resolve hostname: {self.domain}",
                severity=Severity.HIGH,
            )
        except socket.timeout:
            self.logger.error(f"Connection timeout to {self.domain}:{SSL_PORT}")
            self.add_finding(
                category="SSL/TLS Error",
                description=f"Connection timeout to {self.domain}",
                severity=Severity.MEDIUM,
            )
        except ssl.SSLError as e:
            self.logger.error(f"SSL error: {e}")
            self.add_finding(
                category="SSL/TLS Error",
                description=f"SSL connection error: {str(e)}",
                severity=Severity.HIGH,
                recommendation="Check SSL/TLS configuration on the server",
            )
        except Exception as e:
            self.logger.error(f"Error during SSL/TLS analysis: {e}")
            self.add_finding(
                category="SSL/TLS Error",
                description=f"Error during SSL/TLS analysis: {str(e)}",
                severity=Severity.MEDIUM,
            )

        return self.findings

    def _analyze_certificate(self) -> None:
        """Analyze SSL certificate and TLS configuration."""
        context = ssl.create_default_context()

        with socket.create_connection(
            (self.domain, SSL_PORT), timeout=self.timeout
        ) as sock:
            with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                # Get certificate
                cert = ssock.getpeercert()

                # Check certificate expiration
                if cert:
                    not_after = cert.get("notAfter")
                    if not_after:
                        self.add_finding(
                            category="SSL/TLS",
                            description=f"Certificate expires: {not_after}",
                            severity=Severity.INFO,
                            expiration=not_after,
                        )
                        self.logger.debug(f"Certificate expires: {not_after}")

                        # Check if certificate is expiring soon (within 30 days)
                        try:
                            expiry_date = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            )
                            days_until_expiry = (expiry_date - datetime.now()).days

                            if days_until_expiry < 0:
                                self.add_finding(
                                    category="SSL/TLS",
                                    description="Certificate has expired",
                                    severity=Severity.CRITICAL,
                                    recommendation="Renew SSL certificate immediately",
                                )
                            elif days_until_expiry < 30:
                                self.add_finding(
                                    category="SSL/TLS",
                                    description=f"Certificate expires in {days_until_expiry} days",
                                    severity=Severity.HIGH,
                                    recommendation="Renew SSL certificate soon",
                                )
                        except ValueError:
                            pass

                # Check TLS version
                version = ssock.version()
                if version != RECOMMENDED_TLS_VERSION:
                    severity = (
                        Severity.MEDIUM if version in ["TLSv1.2"] else Severity.HIGH
                    )
                    self.add_finding(
                        category="SSL/TLS",
                        description=f"Using {version} - Recommend upgrading to {RECOMMENDED_TLS_VERSION}",
                        severity=severity,
                        recommendation=f"Upgrade to {RECOMMENDED_TLS_VERSION} for better security",
                        current_version=version,
                        recommended_version=RECOMMENDED_TLS_VERSION,
                    )
                    self.logger.warning(
                        f"Using {version}, recommend {RECOMMENDED_TLS_VERSION}"
                    )
                else:
                    self.add_finding(
                        category="SSL/TLS",
                        description=f"Using recommended {version}",
                        severity=Severity.INFO,
                    )

                # Check cipher suite
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]

                    # Check for weak ciphers
                    for weak_cipher in WEAK_CIPHERS:
                        if weak_cipher in cipher_name:
                            self.add_finding(
                                category="SSL/TLS",
                                description=f"Weak cipher suite detected: {cipher_name}",
                                severity=Severity.HIGH,
                                recommendation="Disable weak cipher suites",
                                cipher=cipher_name,
                            )
                            self.logger.warning(f"Weak cipher detected: {cipher_name}")
                            break
                    else:
                        self.add_finding(
                            category="SSL/TLS",
                            description=f"Cipher suite: {cipher_name}",
                            severity=Severity.INFO,
                            cipher=cipher_name,
                        )
