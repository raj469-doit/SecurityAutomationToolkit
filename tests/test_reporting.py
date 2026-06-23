"""
Security Automation Toolkit - Reporting Module Validation Suite
Performs local, deterministic logic verification on the ComplianceReporter engine.
"""

import os
import unittest
from unittest.mock import mock_open, patch, MagicMock
import logging

# Import the module under test
from generate_report import ComplianceReporter


class TestComplianceReporter(unittest.TestCase):
    """Encapsulates unit and behavioral verification methods for ComplianceReporter."""

    def setUp(self):
        """Assembles repeatable mock findings payloads to simulate scanner execution outcomes."""
        logging.basicConfig(level=logging.INFO)
        
        # Current Scan Payload
        self.mock_findings = {
            "target": "https://example-realestate.com",
            "final_score": 85,
            "vulnerabilities": [
                {
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "severity": "High",
                    "description": "Strict-Transport-Security and Content-Security-Policy present.",
                    "remediation": "Configure HSTS headers natively."
                },
                {
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "severity": "Medium",
                    "description": "TLS 1.2 supported but TLS 1.3 preferred.",
                    "remediation": "Update cryptographic cipher configurations."
                }
            ]
        }

        # Historical Baseline Payload (for delta testing)
        self.mock_baseline = {
            "target": "https://example-realestate.com",
            "final_score": 90,
            "vulnerabilities": [
                {
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "severity": "Medium",
                    "description": "TLS 1.2 supported but TLS 1.3 preferred.",
                    "remediation": "Update cryptographic cipher configurations."
                },
                {
                    "owasp_category": "A01:2021-Broken Access Control",
                    "severity": "Low",
                    "description": "Old exposed git metadata directory.",
                    "remediation": "Remove .git folder from public root."
                }
            ]
        }
        
        self.reporter = ComplianceReporter(findings=self.mock_findings)

    def test_reporter_initialization_without_baseline(self):
        """Validates that findings are ingested into state and deltas fall back gracefully."""
        self.assertEqual(self.reporter.findings["target"], "https://example-realestate.com")
        self.assertEqual(self.reporter.deltas["score_delta"], 0)
        self.assertEqual(len(self.reporter.deltas["new"]), 0)

    def test_historical_differential_math(self):
        """Verifies that set operations accurately determine newly added vs resolved issues."""
        reporter_with_history = ComplianceReporter(findings=self.mock_findings, baseline=self.mock_baseline)
        
        # Score dropped from 90 to 85 -> delta should be -5
        self.assertEqual(reporter_with_history.deltas["score_delta"], -5)
        
        # High severity issue is in current but not in baseline -> New
        self.assertEqual(len(reporter_with_history.deltas["new"]), 1)
        self.assertEqual(reporter_with_history.deltas["new"][0]["severity"], "High")
        
        # Broken Access Control was in baseline but is gone now -> Fixed
        self.assertEqual(len(reporter_with_history.deltas["fixed"]), 1)
        self.assertEqual(reporter_with_history.deltas["fixed"][0]["owasp_category"], "A01:2021-Broken Access Control")

    def test_executive_markdown_generation(self):
        """Validates generation of clean, descriptive markdown strings for management tracking."""
        reporter_with_history = ComplianceReporter(findings=self.mock_findings, baseline=self.mock_baseline)
        markdown_output = reporter_with_history.generate_markdown_summary()
        
        self.assertIn("# Executive Security Briefing:", markdown_output)
        self.assertIn("-5 vs baseline", markdown_output)
        self.assertIn("Newly Introduced Exposures", markdown_output)
        self.assertIn("Resolved Vulnerabilities", markdown_output)

    @patch("os.makedirs")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_html_report_generation_flow(self, mock_file, mock_exists, mock_makedirs):
        """Verifies report generation compiles the HTML string structure and commits to disk safely."""
        mock_exists.return_value = False
        output_path = "outputs/scan_report.html"

        # Execute html reporting pipeline
        self.reporter.generate_html(output_path=output_path)

        # Assert path validation operations
        mock_exists.assert_called_once_with("outputs")
        mock_makedirs.assert_called_once_with("outputs", exist_ok=True)
        mock_file.assert_called_once_with(output_path, "w", encoding="utf-8")
        
        # Gather written buffer contents
        handle = mock_file()
        written_content = "".join([call[0][0] for call in handle.write.call_args_list])

        # Confirm modified Phase 3 layout structures are verified
        self.assertIn("https://example-realestate.com", written_content)
        self.assertIn("85/100", written_content)
        self.assertIn("Security Assessment Dashboard", written_content) # Matches updated header
        self.assertIn("chart-container", written_content)              # Matches visual metric widget

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", side_effect=IOError("Permission denied on write stream"))
    def test_report_generation_exception_handling(self, mock_file, mock_exists):
        """Guarantees that filesystem permission bugs or IO exceptions are caught gracefully."""
        output_path = "/protected_root/scan_report.html"
        
        try:
            self.reporter.generate_html(output_path=output_path)
        except Exception as e:
            self.fail(f"ComplianceReporter leaked an raw exception to the runtime engine: {e}")


if __name__ == "__main__":
    unittest.main()
