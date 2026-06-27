"""
Security Automation Toolkit - Reporting module tests.
Tests ComplianceReporter logic without hitting the filesystem or network.
"""

import unittest
from unittest.mock import mock_open, patch
import logging

from generate_report import ComplianceReporter


class TestComplianceReporter(unittest.TestCase):
    """Unit tests for ComplianceReporter."""

    def setUp(self):
        """Set up shared findings and baseline fixtures."""
        logging.basicConfig(level=logging.INFO)

        self.mock_findings = {
            "target": "https://example.com",
            "final_score": 85,
            "vulnerabilities": [
                {
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "severity": "High",
                    "description": "Missing Strict-Transport-Security header.",
                    "remediation": "Configure HSTS on your server.",
                },
                {
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "severity": "Medium",
                    "description": "TLS 1.2 in use; TLS 1.3 preferred.",
                    "remediation": "Update cipher configuration.",
                },
            ],
        }

        self.mock_baseline = {
            "target": "https://example.com",
            "final_score": 90,
            "vulnerabilities": [
                {
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "severity": "Medium",
                    "description": "TLS 1.2 in use; TLS 1.3 preferred.",
                    "remediation": "Update cipher configuration.",
                },
                {
                    "owasp_category": "A01:2021-Broken Access Control",
                    "severity": "Low",
                    "description": "Exposed .git metadata directory.",
                    "remediation": "Remove .git from public web root.",
                },
            ],
        }

        self.reporter = ComplianceReporter(findings=self.mock_findings)

    def test_reporter_initialization_without_baseline(self):
        """Findings are stored and deltas default to zero without baseline."""
        self.assertEqual(
            self.reporter.findings["target"], "https://example.com"
        )
        self.assertEqual(self.reporter.deltas["score_delta"], 0)
        self.assertEqual(len(self.reporter.deltas["new"]), 0)

    def test_historical_differential_math(self):
        """Delta logic correctly identifies new and fixed issues."""
        r = ComplianceReporter(
            findings=self.mock_findings, baseline=self.mock_baseline
        )

        # Score dropped 90 → 85
        self.assertEqual(r.deltas["score_delta"], -5)
        # HSTS issue is new
        self.assertEqual(len(r.deltas["new"]), 1)
        self.assertEqual(r.deltas["new"][0]["severity"], "High")
        # Broken Access Control was fixed
        self.assertEqual(len(r.deltas["fixed"]), 1)
        self.assertEqual(
            r.deltas["fixed"][0]["owasp_category"],
            "A01:2021-Broken Access Control",
        )

    def test_executive_markdown_generation(self):
        """Markdown output has score, delta, and change section headers."""
        r = ComplianceReporter(
            findings=self.mock_findings, baseline=self.mock_baseline
        )
        md = r.generate_markdown_summary()

        self.assertIn("# Security Report:", md)
        self.assertIn("-5 vs previous scan", md)
        self.assertIn("New Issues", md)
        self.assertIn("Fixed Issues", md)

    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_html_report_generation_flow(self, mock_file, mock_makedirs):
        """HTML report is written to the correct path with expected content."""
        output_path = "outputs/scan_report.html"

        self.reporter.generate_html(output_path=output_path)

        mock_makedirs.assert_called_once_with("outputs", exist_ok=True)
        mock_file.assert_called_once_with(output_path, "w", encoding="utf-8")

        handle = mock_file()
        written = "".join(
            call[0][0] for call in handle.write.call_args_list
        )
        self.assertIn("https://example.com", written)
        self.assertIn("85/100", written)
        self.assertIn("Security Report", written)
        self.assertIn("chart-container", written)

    @patch("os.path.exists", return_value=True)
    @patch(
        "builtins.open",
        side_effect=IOError("Permission denied"),
    )
    def test_report_generation_exception_handling(
        self, mock_file, mock_exists
    ):
        """IO errors during report generation are caught, not raised."""
        try:
            self.reporter.generate_html("/protected/report.html")
        except Exception as e:
            self.fail(f"generate_html raised an unexpected exception: {e}")


if __name__ == "__main__":
    unittest.main()
