"""API endpoint discovery module."""

from typing import List
from urllib.parse import urljoin
import requests
from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.utils.constants import COMMON_API_PATHS, HTTP_METHODS


class APIScanner(BaseModule):
    """
    Discovers and tests API endpoints.

    Checks:
        - Common API paths
        - Allowed HTTP methods
        - API endpoint responses
    """

    def scan(self) -> List[Finding]:
        """
        Perform API endpoint discovery.

        Returns:
            List of findings from API discovery
        """
        self.logger.info(f"Starting API discovery for {self.target_url}")

        for path in COMMON_API_PATHS:
            url = urljoin(self.target_url, path)
            try:
                self._test_endpoint(url, path)
            except requests.exceptions.Timeout:
                self.logger.debug(f"Timeout testing {path}")
                continue
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Error testing {path}: {e}")
                continue
            except Exception as e:
                self.logger.debug(f"Unexpected error testing {path}: {e}")
                continue

        return self.findings

    def _test_endpoint(self, url: str, path: str) -> None:
        """
        Test an API endpoint with various HTTP methods.

        Args:
            url: Full URL to test
            path: Path component for logging
        """
        # Test OPTIONS method first for endpoint discovery
        try:
            options_response = self.session.options(url, timeout=self.timeout)

            if "Allow" in options_response.headers:
                allowed_methods = options_response.headers["Allow"]
                self.add_finding(
                    category="API Discovery",
                    description=f"API endpoint found: {path}",
                    severity=Severity.INFO,
                    recommendation="Review API endpoints for proper authentication and authorization",
                    endpoint=path,
                    allowed_methods=allowed_methods,
                )
                self.logger.info(
                    f"API endpoint found: {path} - Methods: {allowed_methods}"
                )
                return
        except requests.exceptions.RequestException:
            pass

        # Test common HTTP methods
        found = False
        for method in HTTP_METHODS:
            try:
                response = self.session.request(method, url, timeout=self.timeout)

                # Consider 2xx, 3xx, 401, 403, 405 as indicators the endpoint exists
                if response.status_code not in [404, 500, 502, 503, 504]:
                    if not found:
                        self.add_finding(
                            category="API Discovery",
                            description=f"API endpoint responds: {path}",
                            severity=Severity.INFO,
                            recommendation="Review API endpoints for proper authentication and authorization",
                            endpoint=path,
                            method=method,
                            status_code=response.status_code,
                        )
                        self.logger.info(
                            f"API endpoint responds: {path} ({method}: {response.status_code})"
                        )
                        found = True

                    # Check for overly permissive CORS
                    if "Access-Control-Allow-Origin" in response.headers:
                        cors_value = response.headers["Access-Control-Allow-Origin"]
                        if cors_value == "*":
                            self.add_finding(
                                category="API Security",
                                description=f"Overly permissive CORS policy on {path}",
                                severity=Severity.MEDIUM,
                                recommendation="Restrict CORS to specific origins instead of using wildcard (*)",
                                endpoint=path,
                                cors_origin=cors_value,
                            )
                            self.logger.warning(
                                f"Permissive CORS on {path}: {cors_value}"
                            )

            except requests.exceptions.RequestException:
                continue
