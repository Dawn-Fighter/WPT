"""JavaScript security analysis module."""

from typing import List, Optional
import re
import requests
from wpt.modules.base_module import BaseModule, Finding, Severity
from wpt.utils.constants import JS_VULN_PATTERNS

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


class JSAnalyzer(BaseModule):
    """
    Analyzes JavaScript for potential vulnerabilities.

    Checks:
        - Hardcoded credentials
        - Unsafe DOM manipulation
        - eval() usage
        - Possible XSS vectors
        - Data exposure via console.log
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.driver: Optional[webdriver.Chrome] = None

    def scan(self) -> List[Finding]:
        """
        Perform JavaScript security analysis.

        Returns:
            List of findings from JavaScript analysis
        """
        self.logger.info(f"Starting JavaScript analysis for {self.target_url}")

        if not SELENIUM_AVAILABLE:
            self.logger.warning("Selenium not available, using basic analysis only")
            self._basic_analysis()
        else:
            try:
                self._setup_selenium()
                self._selenium_analysis()
            except Exception as e:
                self.logger.error(
                    f"Selenium analysis failed: {e}, falling back to basic analysis"
                )
                self._basic_analysis()
            finally:
                self._cleanup_selenium()

        return self.findings

    def _setup_selenium(self) -> None:
        """Initialize Selenium WebDriver."""
        if not SELENIUM_AVAILABLE:
            return

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-logging")
        chrome_options.add_argument("--log-level=3")

        self.driver = webdriver.Chrome(options=chrome_options)
        self.logger.debug("Selenium WebDriver initialized")

    def _cleanup_selenium(self) -> None:
        """Clean up Selenium WebDriver."""
        if self.driver:
            try:
                self.driver.quit()
                self.logger.debug("Selenium WebDriver closed")
            except Exception as e:
                self.logger.debug(f"Error closing WebDriver: {e}")
            finally:
                self.driver = None

    def _basic_analysis(self) -> None:
        """Perform basic JavaScript analysis without Selenium."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)

            # Extract inline scripts and script URLs from HTML
            script_pattern = r"<script[^>]*>(.*?)</script>"
            inline_scripts = re.findall(
                script_pattern, response.text, re.DOTALL | re.IGNORECASE
            )

            for script in inline_scripts:
                if script.strip():
                    self._analyze_js_content(script, "inline")

            # Find external scripts
            src_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
            script_urls = re.findall(src_pattern, response.text, re.IGNORECASE)

            for src in script_urls[:10]:  # Limit to first 10 external scripts
                self._fetch_and_analyze_script(src)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error during basic JS analysis: {e}")
            self.add_finding(
                category="JavaScript Analysis Error",
                description=f"Error during JavaScript analysis: {str(e)}",
                severity=Severity.LOW,
            )

    def _selenium_analysis(self) -> None:
        """Perform JavaScript analysis using Selenium."""
        if not self.driver:
            return

        try:
            self.driver.get(self.target_url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # Collect all script elements
            scripts = self.driver.find_elements(By.TAG_NAME, "script")

            for script in scripts:
                # Check inline scripts
                inline_content = script.get_attribute("innerHTML")
                if inline_content:
                    self._analyze_js_content(inline_content, "inline")

                # Check external scripts
                src = script.get_attribute("src")
                if src:
                    self._fetch_and_analyze_script(src)

        except Exception as e:
            self.logger.error(f"Error during Selenium JS analysis: {e}")
            raise

    def _fetch_and_analyze_script(self, url: str) -> None:
        """
        Fetch and analyze an external JavaScript file.

        Args:
            url: URL of the JavaScript file
        """
        try:
            # Make URL absolute if needed
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = self.target_url.rstrip("/") + url

            response = self.session.get(url, timeout=self.timeout)
            self._analyze_js_content(response.text, url)

        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Error fetching script {url}: {e}")

    def _analyze_js_content(self, content: str, source: str) -> None:
        """
        Analyze JavaScript content for vulnerabilities.

        Args:
            content: JavaScript code to analyze
            source: Source identifier (URL or 'inline')
        """
        for vuln_type, pattern in JS_VULN_PATTERNS.items():
            matches = re.findall(pattern, content)

            if matches:
                # Determine severity based on vulnerability type
                severity = Severity.INFO
                recommendation = None

                if vuln_type == "Hardcoded Credentials":
                    severity = Severity.HIGH
                    recommendation = "Remove hardcoded credentials and use secure credential management"
                elif vuln_type == "Unsafe DOM":
                    severity = Severity.MEDIUM
                    recommendation = "Use safe DOM manipulation methods like textContent instead of innerHTML"
                elif vuln_type == "Eval Usage":
                    severity = Severity.MEDIUM
                    recommendation = "Avoid using eval() as it can lead to code injection vulnerabilities"
                elif vuln_type == "Possible XSS":
                    severity = Severity.MEDIUM
                    recommendation = "Validate and sanitize user input when using location properties"
                elif vuln_type == "Data Exposure":
                    severity = Severity.LOW
                    recommendation = "Remove console.log statements in production code"

                source_label = source if source != "inline" else "inline script"
                self.add_finding(
                    category="JavaScript Security",
                    description=f"Potential {vuln_type} detected in {source_label}",
                    severity=severity,
                    recommendation=recommendation,
                    vulnerability_type=vuln_type,
                    source=source,
                    match_count=len(matches),
                )
                self.logger.debug(
                    f"Found {vuln_type} in {source_label} ({len(matches)} matches)"
                )
