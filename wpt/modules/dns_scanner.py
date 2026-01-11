"""DNS enumeration and subdomain discovery module."""

from typing import List, Set
import dns.resolver
from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.utils.constants import COMMON_SUBDOMAINS, DNS_RECORD_TYPES


class DNSScanner(BaseModule):
    """
    Performs DNS enumeration and subdomain discovery.

    Checks:
        - DNS record types (A, AAAA, MX, NS, TXT, SOA)
        - Common subdomain enumeration
        - DNS configuration issues
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subdomains: Set[str] = set()

    def scan(self) -> List[Finding]:
        """
        Perform DNS enumeration.

        Returns:
            List of findings from DNS analysis
        """
        self.logger.info(f"Starting DNS enumeration for {self.domain}")

        try:
            self._check_dns_records()
            self._enumerate_subdomains()
        except Exception as e:
            self.logger.error(f"Error during DNS enumeration: {e}")
            self.add_finding(
                category="DNS Error",
                description=f"Error during DNS enumeration: {str(e)}",
                severity=Severity.LOW,
            )

        return self.findings

    def _check_dns_records(self) -> None:
        """Check various DNS record types for the main domain."""
        for record_type in DNS_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                for rdata in answers:
                    self.add_finding(
                        category="DNS Records",
                        description=f"{record_type} record: {rdata}",
                        severity=Severity.INFO,
                        record_type=record_type,
                        value=str(rdata),
                    )
                    self.logger.debug(f"Found {record_type} record: {rdata}")
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {record_type} records found for {self.domain}")
                continue
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"Domain {self.domain} does not exist")
                self.add_finding(
                    category="DNS Error",
                    description=f"Domain {self.domain} does not exist",
                    severity=Severity.HIGH,
                )
                break
            except dns.resolver.Timeout:
                self.logger.warning(f"DNS timeout for {record_type} query")
                continue
            except Exception as e:
                self.logger.debug(f"Error checking {record_type} record: {e}")
                continue

    def _enumerate_subdomains(self) -> None:
        """Enumerate common subdomains."""
        self.logger.info("Starting subdomain enumeration")
        found_count = 0

        for subdomain in COMMON_SUBDOMAINS:
            try:
                hostname = f"{subdomain}.{self.domain}"
                answers = dns.resolver.resolve(hostname, "A")

                # Subdomain exists
                self.subdomains.add(hostname)
                found_count += 1

                ips = [str(rdata) for rdata in answers]
                self.add_finding(
                    category="Subdomain Discovery",
                    description=f"Found subdomain: {hostname}",
                    severity=Severity.INFO,
                    recommendation="Review subdomain for security misconfigurations",
                    subdomain=hostname,
                    ips=ips,
                )
                self.logger.debug(f"Found subdomain: {hostname} -> {ips}")

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.resolver.Timeout:
                self.logger.debug(f"Timeout checking subdomain: {subdomain}")
                continue
            except Exception as e:
                self.logger.debug(f"Error checking subdomain {subdomain}: {e}")
                continue

        if found_count > 0:
            self.logger.info(f"Found {found_count} subdomains")
        else:
            self.logger.info("No common subdomains found")
