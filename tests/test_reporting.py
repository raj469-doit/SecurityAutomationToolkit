"""
Security Automation Toolkit - Reporting module tests.
Tests ComplianceReporter logic without hitting disk or network.
"""

from typing import Any, Dict
from unittest.mock import mock_open, patch

import pytest

from generate_report import ComplianceReporter

# ── Fixtures ──────────────────────────────────────────────


@pytest.fixture
def findings() -> Dict[str, Any]:
    """Current scan findings fixture."""
    return {
        "target": "https://example.com",
        "final_score": 85,
        "vulnerabilities": [
            {
                "owasp_category": (
                    "A05:2021-Security Misconfiguration"
                ),
                "severity": "High",
                "description": (
                    "Missing Strict-Transport-Security header."
                ),
                "remediation": "Configure HSTS on your server.",
            },
            {
                "owasp_category": (
                    "A02:2021-Cryptographic Failures"
                ),
                "severity": "Medium",
                "description": (
                    "TLS 1.2 in use; TLS 1.3 preferred."
                ),
                "remediation": "Update cipher configuration.",
            },
        ],
    }


@pytest.fixture
def baseline() -> Dict[str, Any]:
    """Previous scan baseline fixture for delta testing."""
    return {
        "target": "https://example.com",
        "final_score": 90,
        "vulnerabilities": [
            {
                "owasp_category": (
                    "A02:2021-Cryptographic Failures"
                ),
                "severity": "Medium",
                "description": (
                    "TLS 1.2 in use; TLS 1.3 preferred."
                ),
                "remediation": "Update cipher configuration.",
            },
            {
                "owasp_category": (
                    "A01:2021-Broken Access Control"
                ),
                "severity": "Low",
                "description": (
                    "Exposed .git metadata directory."
                ),
                "remediation": (
                    "Remove .git from public web root."
                ),
            },
        ],
    }


# ── Tests ─────────────────────────────────────────────────


def test_init_without_baseline(
    findings: Dict[str, Any],
) -> None:
    """Findings stored; deltas default to zero without baseline."""
    r = ComplianceReporter(findings=findings)

    assert r.findings["target"] == "https://example.com"
    assert r.deltas["score_delta"] == 0
    assert len(r.deltas["new"]) == 0


def test_historical_delta_math(
    findings: Dict[str, Any],
    baseline: Dict[str, Any],
) -> None:
    """Delta logic identifies new and fixed issues correctly."""
    r = ComplianceReporter(
        findings=findings, baseline=baseline
    )

    # Score dropped 90 -> 85
    assert r.deltas["score_delta"] == -5
    # HSTS issue is new
    assert len(r.deltas["new"]) == 1
    assert r.deltas["new"][0]["severity"] == "High"
    # Broken Access Control was fixed
    assert len(r.deltas["fixed"]) == 1
    assert (
        r.deltas["fixed"][0]["owasp_category"]
        == "A01:2021-Broken Access Control"
    )


def test_markdown_generation(
    findings: Dict[str, Any],
    baseline: Dict[str, Any],
) -> None:
    """Markdown output has score, delta, and change headings."""
    r = ComplianceReporter(
        findings=findings, baseline=baseline
    )
    md = r.generate_markdown_summary()

    assert "# Security Report:" in md
    assert "-5 vs previous scan" in md
    assert "New Issues" in md
    assert "Fixed Issues" in md


@patch("os.makedirs")
@patch("builtins.open", new_callable=mock_open)
def test_html_report_generation(
    mock_file: Any,
    mock_makedirs: Any,
    findings: Dict[str, Any],
) -> None:
    """HTML report is written with expected content."""
    output_path = "outputs/scan_report.html"
    r = ComplianceReporter(findings=findings)
    r.generate_html(output_path=output_path)

    mock_makedirs.assert_called_once_with(
        "outputs", exist_ok=True
    )
    mock_file.assert_called_once_with(
        output_path, "w", encoding="utf-8"
    )

    handle = mock_file()
    written = "".join(
        call[0][0]
        for call in handle.write.call_args_list
    )
    assert "https://example.com" in written
    assert "85/100" in written
    assert "Security Report" in written
    assert "chart-container" in written


@patch("os.path.exists", return_value=True)
@patch(
    "builtins.open",
    side_effect=IOError("Permission denied"),
)
def test_html_report_handles_io_error(
    mock_file: Any,
    mock_exists: Any,
    findings: Dict[str, Any],
) -> None:
    """IO errors during report generation are caught."""
    r = ComplianceReporter(findings=findings)
    # Should not raise
    r.generate_html("/protected/report.html")
