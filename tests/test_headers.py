from unittest.mock import MagicMock, patch

from security_score import SecurityScanner


@patch('security_score.requests.get')
def test_scanner_flags_missing_security_headers(mock_get):
    """
    OWASP A05 (Security Misconfiguration)
    Verifies that missing security headers are recorded in findings.
    """
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Server": "InsecureServer/1.0",
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Plain page</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://vulnerable.com")

    expected_missing = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]
    for header in expected_missing:
        assert header in results["missing_headers"]


@patch('security_score.requests.get')
def test_scanner_passes_fully_hardened_headers(mock_get):
    """
    Verifies that a site with all required headers produces no header findings.
    """
    mock_response = MagicMock()
    mock_response.headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    mock_response.cookies = []
    mock_response.text = "<html><body>Hardened</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://secure.com")

    assert len(results["missing_headers"]) == 0
