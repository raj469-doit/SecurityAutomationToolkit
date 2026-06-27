from unittest.mock import MagicMock, patch

import requests

from security_score import SecurityScanner


@patch('security_score.requests.get')
def test_scanner_flags_insecure_http_protocol(mock_get):
    """
    Ensures that an http:// URL is recorded as not TLS-secured (OWASP A04).
    """
    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = []
    mock_response.text = "<html><body>Insecure</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("http://insecure.com")

    assert results["tls_secured"] is False
    assert len(results["errors"]) == 0


@patch('security_score.requests.get')
def test_scanner_validates_secure_https_protocol(mock_get):
    """
    Ensures that an https:// URL is recorded as TLS-secured.
    """
    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = []
    mock_response.text = "<html><body>Secure</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://secure.com")

    assert results["tls_secured"] is True
    assert len(results["errors"]) == 0


@patch('security_score.requests.get')
def test_scanner_handles_ssl_errors_gracefully(mock_get):
    """
    Ensures that SSL errors are caught and returned in the findings dict
    rather than crashing the scanner.
    """
    mock_get.side_effect = requests.exceptions.SSLError(
        "Certificate verification failed"
    )

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://expired-cert.com")

    assert "Connection failed" in results["errors"][0]
