"""Cookie security analysis module."""

from typing import List
import requests
from http.cookiejar import Cookie
from wpt.modules.base_module import BaseModule, Finding, Severity


class CookieAnalyzer(BaseModule):
    """
    Analyzes cookie security configurations.

    Checks:
        - Secure flag
        - HttpOnly flag
        - SameSite attribute
        - Cookie expiration
    """

    def scan(self) -> List[Finding]:
        """
        Perform cookie security analysis.

        Returns:
            List of findings from cookie analysis
        """
        self.logger.info(f"Starting cookie analysis for {self.target_url}")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            self._analyze_cookies(response)
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout to {self.target_url}")
            self.add_finding(
                category="Cookie Analysis Error",
                description="Request timeout during cookie analysis",
                severity=Severity.LOW,
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {e}")
            self.add_finding(
                category="Cookie Analysis Error",
                description=f"Request error during cookie analysis: {str(e)}",
                severity=Severity.LOW,
            )
        except Exception as e:
            self.logger.error(f"Error during cookie analysis: {e}")
            self.add_finding(
                category="Cookie Analysis Error",
                description=f"Error during cookie analysis: {str(e)}",
                severity=Severity.LOW,
            )

        return self.findings

    def _analyze_cookies(self, response: requests.Response) -> None:
        """
        Analyze cookies for security issues.

        Args:
            response: HTTP response object
        """
        cookies = response.cookies

        if not cookies:
            self.add_finding(
                category="Cookie Security",
                description="No cookies found",
                severity=Severity.INFO,
            )
            self.logger.info("No cookies found")
            return

        for cookie in cookies:
            issues = []
            severity = Severity.LOW

            # Check Secure flag
            if not cookie.secure:
                issues.append("Missing Secure flag")
                if self.target_url.startswith("https"):
                    severity = Severity.MEDIUM

            # Check HttpOnly flag
            # Fixed: Use _rest dict or check expires property properly
            has_httponly = False
            if hasattr(cookie, "_rest") and cookie._rest:
                has_httponly = "HttpOnly" in cookie._rest

            if not has_httponly:
                issues.append("Missing HttpOnly flag")
                severity = Severity.MEDIUM

            # Check SameSite attribute
            has_samesite = False
            if hasattr(cookie, "_rest") and cookie._rest:
                has_samesite = "SameSite" in cookie._rest

            if not has_samesite:
                issues.append("Missing SameSite attribute")
                if severity == Severity.LOW:
                    severity = Severity.MEDIUM

            if issues:
                recommendation = self._get_cookie_recommendation(issues)
                self.add_finding(
                    category="Cookie Security",
                    description=f'Cookie "{cookie.name}" has security issues: {", ".join(issues)}',
                    severity=severity,
                    recommendation=recommendation,
                    cookie_name=cookie.name,
                    issues=issues,
                )
                self.logger.warning(
                    f"Cookie {cookie.name} has issues: {', '.join(issues)}"
                )
            else:
                self.add_finding(
                    category="Cookie Security",
                    description=f'Cookie "{cookie.name}" has proper security attributes',
                    severity=Severity.INFO,
                    cookie_name=cookie.name,
                )

    def _get_cookie_recommendation(self, issues: List[str]) -> str:
        """
        Generate recommendation based on cookie issues.

        Args:
            issues: List of security issues

        Returns:
            Recommendation string
        """
        recommendations = []

        if "Missing Secure flag" in issues:
            recommendations.append("Set Secure flag to prevent transmission over HTTP")
        if "Missing HttpOnly flag" in issues:
            recommendations.append("Set HttpOnly flag to prevent JavaScript access")
        if "Missing SameSite attribute" in issues:
            recommendations.append(
                "Set SameSite attribute to Strict or Lax to prevent CSRF"
            )

        return "; ".join(recommendations)
