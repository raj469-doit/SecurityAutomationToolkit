from unittest.mock import MagicMock, patch

from security_score import SecurityScanner


@patch('security_score.requests.get')
def test_scanner_flags_insecure_and_accessible_cookies(mock_get):
    """
    OWASP A04 (Cryptographic Failures)
    Validates that cookies missing HttpOnly and Secure flags are reported.
    """
    vulnerable_cookie = MagicMock()
    vulnerable_cookie.name = "auth_session"
    vulnerable_cookie.secure = False
    vulnerable_cookie.has_nonstandard_attr.return_value = False
    vulnerable_cookie._attributes = {}

    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = [vulnerable_cookie]
    mock_response.text = "<html><body>Portal</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://demo.internal/dashboard")

    assert len(results["cookie_violations"]) == 1
    violation = results["cookie_violations"][0]
    assert violation["cookie_name"] == "auth_session"
    assert "Missing 'Secure' directive" in violation["issues"]
    assert "Missing 'HttpOnly' directive" in violation["issues"]


@patch('security_score.requests.get')
def test_scanner_passes_fully_hardened_cookies(mock_get):
    """
    Ensures compliant cookies do not generate alerts.
    """
    secure_cookie = MagicMock()
    secure_cookie.name = "secure_token"
    secure_cookie.secure = True
    secure_cookie.has_nonstandard_attr.side_effect = (
        lambda attr: attr.lower() == "httponly"
    )

    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = [secure_cookie]
    mock_response.text = "<html><body>Secure</body></html>"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://demo.internal")

    assert len(results["cookie_violations"]) == 0
