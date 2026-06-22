import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner

@patch('requests.get')
def test_scanner_flags_missing_essential_security_headers(mock_get):
    """
    OWASP A02 (Security Misconfiguration)
    Verifies missing defensive headers are properly appended to the vulnerability array.
    """
    # Simulate a web infrastructure completely lacking security defenses
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Server": "InsecureServer/1.0"
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Plain Target Page</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://vulnerable-realestate.com")

    # Assert that all standard evaluated configurations are recorded as missing
    expected_missing = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    for header in expected_missing:
        assert header in results["missing_headers"]


@patch('requests.get')
def test_scanner_passes_fully_hardened_infrastructure_headers(mock_get):
    """
    Verifies that targets configured with strict defensive headers do not trigger flags.
    """
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Hardened Core Portal</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://secure-realestate.com")

    assert len(results["missing_headers"]) == 0
