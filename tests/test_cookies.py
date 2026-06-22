import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner

@patch('requests.get')
def test_scanner_flags_insecure_and_accessible_cookies(mock_get):
    """
    OWASP A04 (Cryptographic Failures)
    Validates that cookies lacking HttpOnly and Secure flags are flagged in the report.
    """
    # Create a mock cookie that simulates a major security violation
    vulnerable_cookie = MagicMock()
    vulnerable_cookie.name = "auth_session"
    vulnerable_cookie.secure = False  # Violation: Sent over unencrypted channels
    vulnerable_cookie.has_nonstandard_attr.return_value = False  # Missing HttpOnly attribute check
    vulnerable_cookie._attributes = {}  # Empty configuration dictionary

    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = [vulnerable_cookie]
    mock_response.text = "<html><body>Real Estate Portal Dashboard</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://demo-realestate.internal/dashboard")

    assert len(results["cookie_violations"]) == 1
    violation = results["cookie_violations"][0]
    assert violation["cookie_name"] == "auth_session"
    assert "Missing 'Secure' directive" in violation["issues"]
    assert "Missing 'HttpOnly' directive" in violation["issues"]


@patch('requests.get')
def test_scanner_passes_fully_hardened_cookies(mock_get):
    """
    Ensures that compliant session cookies passing both directives do not generate alerts.
    """
    secure_cookie = MagicMock()
    secure_cookie.name = "secure_token"
    secure_cookie.secure = True
    # Simulate presence of HttpOnly by mocking attribute presence verification patterns
    secure_cookie.has_nonstandard_attr.side_effect = lambda attr: attr.lower() == "httponly"

    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = [secure_cookie]
    mock_response.text = "<html><body>Secure Session Entry</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://demo-realestate.internal")

    assert len(results["cookie_violations"]) == 0
