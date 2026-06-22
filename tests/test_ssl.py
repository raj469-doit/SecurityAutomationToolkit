import pytest
from unittest.mock import patch, MagicMock
import requests
# Import your newly updated scanner class from security_score.py
from security_score import SecurityScanner 

@patch('requests.get')
def test_scanner_flags_insecure_http_protocol(mock_get):
    """
    Ensures that if the user supplies an unencrypted http:// URL, 
    the engine correctly notes that TLS is False (OWASP A04).
    """
    # 1. Setup our mock server payload
    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = []
    mock_response.text = "<html><body>Target Real Estate Site</body></html>"
    mock_get.return_value = mock_response

    # 2. Run the scanner against an insecure mockup URL
    scanner = SecurityScanner()
    results = scanner.scan_endpoint("http://insecure-realestate-portal.com")

    # 3. Assert that our engine caught that it was NOT using HTTPS
    assert results["tls_secured"] is False
    assert len(results["errors"]) == 0


@patch('requests.get')
def test_scanner_validates_secure_https_protocol(mock_get):
    """
    Ensures that if the user supplies a secure https:// URL,
    the engine flags TLS as True.
    """
    # 1. Setup our mock server payload
    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = []
    mock_response.text = "<html><body>Target Real Estate Site</body></html>"
    mock_get.return_value = mock_response

    # 2. Run the scanner against a secure mockup URL
    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://secure-realestate-portal.com")

    # 3. Assert that our engine caught that it WAS using HTTPS
    assert results["tls_secured"] is True
    assert len(results["errors"]) == 0


@patch('requests.get')
def test_scanner_handles_ssl_handshake_network_failures(mock_get):
    """
    Production-readiness test: Ensures that if an external server drops or
    has an invalid/expired SSL certificate, your tool safely catches the error 
    instead of crashing the entire script engine.
    """
    # 1. Force the mock network request to throw an actual RequestException error
    mock_get.side_effect = requests.exceptions.SSLError("Certificate verification failed")

    # 2. Run the scan
    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://expired-cert-realestate.com")

    # 3. Assert that the error was gracefully captured inside the output dictionary
    assert "Connection failure" in results["errors"][0]
