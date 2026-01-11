"""Web Application Firewall detection module."""

from typing import List
import requests
from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.utils.constants import WAF_SIGNATURES


class WAFDetector(BaseModule):
    """
    Detects presence of Web Application Firewall.

    Checks:
        - Response headers for WAF signatures
        - Cookies for WAF signatures
        - Common WAF fingerprints
    """

    def scan(self) -> List[Finding]:
        """
        Perform WAF detection.

        Returns:
            List of findings from WAF detection
        """
        self.logger.info(f"Starting WAF detection for {self.target_url}")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            self._detect_waf(response)
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout to {self.target_url}")
            self.add_finding(
                category="WAF Detection Error",
                description="Request timeout during WAF detection",
                severity=Severity.LOW,
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {e}")
            self.add_finding(
                category="WAF Detection Error",
                description=f"Request error during WAF detection: {str(e)}",
                severity=Severity.LOW,
            )
        except Exception as e:
            self.logger.error(f"Error during WAF detection: {e}")
            self.add_finding(
                category="WAF Detection Error",
                description=f"Error during WAF detection: {str(e)}",
                severity=Severity.LOW,
            )

        return self.findings

    def _detect_waf(self, response: requests.Response) -> None:
        """
        Detect WAF from response headers and cookies.

        Args:
            response: HTTP response object
        """
        headers = str(response.headers).lower()
        cookies = str(response.cookies).lower()

        detected_wafs = set()

        for waf, signatures in WAF_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in headers or signature.lower() in cookies:
                    detected_wafs.add(waf)
                    self.logger.info(f"Detected {waf} WAF")
                    break

        if detected_wafs:
            for waf in detected_wafs:
                self.add_finding(
                    category="WAF Detection",
                    description=f"Detected {waf} Web Application Firewall",
                    severity=Severity.INFO,
                    recommendation="WAF presence indicates security measures are in place",
                    waf_name=waf,
                )
        else:
            self.add_finding(
                category="WAF Detection",
                description="No known WAF detected",
                severity=Severity.INFO,
                recommendation="Consider implementing a WAF for additional protection",
            )
            self.logger.info("No known WAF detected")
