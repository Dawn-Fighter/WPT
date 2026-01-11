"""Report generation module."""

from typing import List, Dict, Any
from datetime import datetime
import json
from collections import defaultdict
from wpt.modules.base_module import Finding, Severity


class Reporter:
    """
    Generates security scan reports in various formats.

    Supports:
        - Console output
        - Plain text files
        - JSON files
        - HTML reports
        - CSV files
    """

    def __init__(self, target_url: str, findings: List[Finding]):
        """
        Initialize reporter.

        Args:
            target_url: The scanned target URL
            findings: List of all findings from scan
        """
        self.target_url = target_url
        self.findings = findings
        self.scan_time = datetime.now()

    def print_console_report(self) -> None:
        """Print formatted report to console."""
        print("\n" + "=" * 70)
        print("       WPT - Web Penetration Testing Tool - Scan Report")
        print("=" * 70)
        print(f"\nTarget: {self.target_url}")
        print(f"Scan completed: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total findings: {len(self.findings)}")

        # Group findings by category
        findings_by_category = self._group_by_category()

        # Print summary by severity
        self._print_severity_summary()

        # Print detailed findings
        print("\n" + "-" * 70)
        print("DETAILED FINDINGS")
        print("-" * 70)

        for category in sorted(findings_by_category.keys()):
            findings = findings_by_category[category]
            print(f"\n[{category}]")

            for finding in findings:
                severity_marker = self._get_severity_marker(finding.severity)
                print(f"  {severity_marker} {finding.description}")

                if finding.recommendation:
                    print(f"     → Recommendation: {finding.recommendation}")

        print("\n" + "=" * 70)

    def save_text_report(self, filename: str) -> None:
        """
        Save report as plain text file.

        Args:
            filename: Output filename
        """
        with open(filename, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("  WPT - Web Penetration Testing Tool - Scan Report\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Scan completed: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total findings: {len(self.findings)}\n\n")

            # Severity summary
            severity_counts = self._count_by_severity()
            f.write("Findings by Severity:\n")
            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    f.write(f"  {severity.value.upper()}: {count}\n")

            # Detailed findings
            f.write("\n" + "-" * 70 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("-" * 70 + "\n\n")

            findings_by_category = self._group_by_category()
            for category in sorted(findings_by_category.keys()):
                findings = findings_by_category[category]
                f.write(f"\n[{category}]\n")

                for finding in findings:
                    f.write(
                        f"  [{finding.severity.value.upper()}] {finding.description}\n"
                    )
                    if finding.recommendation:
                        f.write(f"     Recommendation: {finding.recommendation}\n")

            f.write("\n" + "=" * 70 + "\n")

    def save_json_report(self, filename: str) -> None:
        """
        Save report as JSON file.

        Args:
            filename: Output filename
        """
        report_data = {
            "target": self.target_url,
            "scan_time": self.scan_time.isoformat(),
            "total_findings": len(self.findings),
            "severity_summary": {
                severity.value: count
                for severity, count in self._count_by_severity().items()
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }

        with open(filename, "w") as f:
            json.dump(report_data, f, indent=2)

    def save_html_report(self, filename: str) -> None:
        """
        Save report as HTML file.

        Args:
            filename: Output filename
        """
        html = self._generate_html()
        with open(filename, "w") as f:
            f.write(html)

    def save_csv_report(self, filename: str) -> None:
        """
        Save report as CSV file.

        Args:
            filename: Output filename
        """
        import csv

        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Severity", "Description", "Recommendation"])

            for finding in self.findings:
                writer.writerow(
                    [
                        finding.category,
                        finding.severity.value,
                        finding.description,
                        finding.recommendation or "",
                    ]
                )

    def _group_by_category(self) -> Dict[str, List[Finding]]:
        """Group findings by category."""
        grouped = defaultdict(list)
        for finding in self.findings:
            grouped[finding.category].append(finding)
        return dict(grouped)

    def _count_by_severity(self) -> Dict[Severity, int]:
        """Count findings by severity level."""
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.severity] += 1
        return dict(counts)

    def _print_severity_summary(self) -> None:
        """Print summary of findings by severity."""
        severity_counts = self._count_by_severity()

        print("\nFindings by Severity:")
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                marker = self._get_severity_marker(severity)
                print(f"  {marker} {severity.value.upper()}: {count}")

    def _get_severity_marker(self, severity: Severity) -> str:
        """Get visual marker for severity level."""
        markers = {
            Severity.CRITICAL: "[!!!]",
            Severity.HIGH: "[!!]",
            Severity.MEDIUM: "[!]",
            Severity.LOW: "[*]",
            Severity.INFO: "[i]",
        }
        return markers.get(severity, "[?]")

    def _generate_html(self) -> str:
        """Generate HTML report."""
        severity_counts = self._count_by_severity()
        findings_by_category = self._group_by_category()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WPT Scan Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ccc; }}
        .critical {{ border-color: #e74c3c; }}
        .high {{ border-color: #e67e22; }}
        .medium {{ border-color: #f39c12; }}
        .low {{ border-color: #3498db; }}
        .info {{ border-color: #95a5a6; }}
        .category {{ font-weight: bold; color: #2c3e50; margin-top: 20px; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.9em; }}
        .recommendation {{ margin-top: 10px; padding: 10px; background: #ecf0f1; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WPT - Web Penetration Testing Tool</h1>
        <h2>Security Scan Report</h2>
    </div>
    
    <div class="summary">
        <p><strong>Target:</strong> {self.target_url}</p>
        <p><strong>Scan Time:</strong> {self.scan_time.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Total Findings:</strong> {len(self.findings)}</p>
        <h3>Severity Summary</h3>
        <ul>
"""

        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                html += f"            <li>{severity.value.upper()}: {count}</li>\n"

        html += """        </ul>
    </div>
    
    <h2>Detailed Findings</h2>
"""

        for category in sorted(findings_by_category.keys()):
            html += f'    <div class="category">{category}</div>\n'

            for finding in findings_by_category[category]:
                severity_class = finding.severity.value
                html += f'    <div class="finding {severity_class}">\n'
                html += f'        <span class="severity {severity_class}">{finding.severity.value.upper()}</span>\n'
                html += f"        <p>{finding.description}</p>\n"

                if finding.recommendation:
                    html += f'        <div class="recommendation"><strong>Recommendation:</strong> {finding.recommendation}</div>\n'

                html += "    </div>\n"

        html += """
</body>
</html>
"""
        return html
