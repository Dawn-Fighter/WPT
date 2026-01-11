"""Main web scanner orchestrator."""

from typing import List, Optional
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from wpt.modules.base_module import Finding
from wpt.modules.dns_scanner import DNSScanner
from wpt.modules.ssl_scanner import SSLScanner
from wpt.modules.waf_detector import WAFDetector
from wpt.modules.api_scanner import APIScanner
from wpt.modules.js_analyzer import JSAnalyzer
from wpt.modules.cookie_analyzer import CookieAnalyzer
from wpt.modules.form_analyzer import FormAnalyzer
from wpt.core.reporter import Reporter
from wpt.utils.logger import setup_logger
from wpt.utils.constants import DEFAULT_TIMEOUT, DEFAULT_THREADS, DEFAULT_USER_AGENT


class WebScanner:
    """
    Main web security scanner orchestrator.

    Coordinates all scanner modules and generates comprehensive reports.
    """

    def __init__(
        self,
        target_url: str,
        threads: int = DEFAULT_THREADS,
        verbose: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        """
        Initialize web scanner.

        Args:
            target_url: Target URL to scan
            threads: Number of concurrent threads (default: 5)
            verbose: Enable verbose logging (default: False)
            timeout: Request timeout in seconds (default: 10)
        """
        # Normalize URL
        self.target_url = (
            target_url if target_url.startswith("http") else f"http://{target_url}"
        )
        self.threads = threads
        self.verbose = verbose
        self.timeout = timeout

        # Parse domain
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc

        # Initialize session with proper settings
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        # Setup logging
        self.logger = setup_logger("WebScanner", verbose=verbose)

        # Storage for findings
        self.all_findings: List[Finding] = []

        self.logger.info(f"Initialized scanner for {self.target_url}")

    def scan(self) -> List[Finding]:
        """
        Perform comprehensive security scan.

        Returns:
            List of all findings from all modules
        """
        self.logger.info(f"Starting comprehensive scan of {self.target_url}")

        # Initialize all scanner modules
        scanners = [
            (
                "DNS Enumeration",
                DNSScanner(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
            (
                "SSL/TLS Analysis",
                SSLScanner(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
            (
                "WAF Detection",
                WAFDetector(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
            (
                "API Discovery",
                APIScanner(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
            (
                "JavaScript Analysis",
                JSAnalyzer(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
            (
                "Cookie Analysis",
                CookieAnalyzer(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
            (
                "Form Analysis",
                FormAnalyzer(
                    self.target_url,
                    self.domain,
                    self.session,
                    timeout=self.timeout,
                    verbose=self.verbose,
                ),
            ),
        ]

        # Run scanners with progress bar
        with tqdm(total=len(scanners), desc="Scanning Progress", unit="module") as pbar:
            for module_name, scanner in scanners:
                self.logger.info(f"Running {module_name}")
                try:
                    findings = scanner.scan()
                    self.all_findings.extend(findings)
                    self.logger.info(
                        f"{module_name} completed with {len(findings)} findings"
                    )
                except Exception as e:
                    self.logger.error(f"Error in {module_name}: {e}")
                finally:
                    pbar.update(1)

        self.logger.info(f"Scan completed. Total findings: {len(self.all_findings)}")
        return self.all_findings

    def generate_report(
        self, output_file: Optional[str] = None, output_format: str = "console"
    ) -> None:
        """
        Generate scan report.

        Args:
            output_file: Output filename (required for file formats)
            output_format: Format (console, txt, json, html, csv)
        """
        reporter = Reporter(self.target_url, self.all_findings)

        if output_format == "console":
            reporter.print_console_report()
        elif output_format == "txt":
            if not output_file:
                output_file = f"wpt_report_{self.domain}.txt"
            reporter.save_text_report(output_file)
            self.logger.info(f"Text report saved to {output_file}")
        elif output_format == "json":
            if not output_file:
                output_file = f"wpt_report_{self.domain}.json"
            reporter.save_json_report(output_file)
            self.logger.info(f"JSON report saved to {output_file}")
        elif output_format == "html":
            if not output_file:
                output_file = f"wpt_report_{self.domain}.html"
            reporter.save_html_report(output_file)
            self.logger.info(f"HTML report saved to {output_file}")
        elif output_format == "csv":
            if not output_file:
                output_file = f"wpt_report_{self.domain}.csv"
            reporter.save_csv_report(output_file)
            self.logger.info(f"CSV report saved to {output_file}")
        else:
            self.logger.error(f"Unknown output format: {output_format}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        if self.session:
            self.session.close()
        return False
