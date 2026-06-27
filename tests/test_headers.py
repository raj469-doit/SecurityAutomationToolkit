from unittest.mock import MagicMock, patch

from security_score import SecurityScanner


@patch('security_score.requests.get')
def test_scanner_flags_missing_security_headers(mock_get):
    """
    OWASP A05 - all 7 required headers missing are recorded.
    """
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Plain</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://vuln.com")

    expected = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-Permitted-Cross-Domain-Policies",
    ]
    for header in expected:
        assert header in results["missing_headers"]


@patch('security_score.requests.get')
def test_scanner_passes_fully_hardened_headers(mock_get):
    """
    A site with all required headers produces no findings.
    """
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "X-Permitted-Cross-Domain-Policies": "none",
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Secure</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://secure.com")

    assert len(results["missing_headers"]) == 0


@patch('security_score.requests.get')
def test_new_owasp_headers_flagged_individually(mock_get):
    """
    3.1 - Each new header is individually flagged when missing.
    """
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        # Include all original 4, omit the 3 new ones
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Partial</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://partial.com")

    assert "Referrer-Policy" in results["missing_headers"]
    assert "Permissions-Policy" in results["missing_headers"]
    assert (
        "X-Permitted-Cross-Domain-Policies"
        in results["missing_headers"]
    )
    # Original 4 should NOT be missing
    assert (
        "Strict-Transport-Security"
        not in results["missing_headers"]
    )
