"""
Security Automation Toolkit - Reporting Module Validation Suite
Performs local, deterministic logic verification on the ComplianceReporter engine.

Architecture Strategy:
- Decoupled Verification: Employs unittest.mock to intercept file system I/O.
- Zero Live Traffic: Validates HTML template rendering without external network requests.
- CI/CD Safe: Fully compatible with automated pipeline execution policies.
"""

import json
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
        
        # Simulated payload mirroring generate_report.py structural contracts
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
                },
                {
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "severity": "Low",
                    "description": "Session cookie missing 'SameSite' attribute configuration.",
                    "remediation": "Append SameSite=Lax attribute."
                }
            ]
        }
        self.reporter = ComplianceReporter(findings=self.mock_findings)

    def test_reporter_initialization(self):
        """Validates that findings data dictionaries are correctly ingested into state."""
        self.assertEqual(self.reporter.findings["target"], "https://example-realestate.com")
        self.assertEqual(self.reporter.findings["final_score"], 85)
        self.assertIn("vulnerabilities", self.reporter.findings)

    @patch("os.makedirs")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_html_report_generation_flow(self, mock_file, mock_exists, mock_makedirs):
        """Verifies report generation compiles the HTML string structure and commits to disk safely."""
        # Setup mocks to simulate that the output directory does not exist yet
        mock_exists.return_value = False
        output_path = "outputs/scan_report.html"

        # Execute the correct HTML report creation routing method name
        self.reporter.generate_html(output_path=output_path)

        # Verify that directory missing conditions were evaluated and handled
        mock_exists.assert_called_once_with("outputs")
        mock_makedirs.assert_called_once_with("outputs", exist_ok=True)

        # Verify that standard file I/O operations were executed against the correct route
        mock_file.assert_called_once_with(output_path, "w", encoding="utf-8")
        
        # Gather written contents to evaluate structural integrity
        handle = mock_file()
        written_content = "".join([call[0][0] for call in handle.write.call_args_list])

        # Validate core template dynamic variables are injected safely
        self.assertIn("https://example-realestate.com", written_content)
        self.assertIn("85/100", written_content)
        self.assertIn("Security Assessment Summary", written_content)
        self.assertIn("A05:2021-Security Misconfiguration", written_content)

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", side_effect=IOError("Permission denied on write stream"))
    def test_report_generation_exception_handling(self, mock_file, mock_exists):
        """Guarantees that filesystem permission bugs or IO exceptions are caught gracefully."""
        output_path = "/protected_root/scan_report.html"
        
        # Verify that an internal IOError doesn't crash the scanning runtime environment
        try:
            self.reporter.generate_html(output_path=output_path)
        except Exception as e:
            self.fail(f"ComplianceReporter leaked a raw exception to the runtime engine: {e}")


if __name__ == "__main__":
    unittest.main()
