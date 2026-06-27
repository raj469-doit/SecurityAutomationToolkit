"""Tests for server version disclosure detection (3.4)."""

from unittest.mock import MagicMock, patch

from security_score import SecurityScanner


@patch('security_score.requests.get')
def test_server_header_version_flagged(mock_get):
    """Server header with a version number is reported."""
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.41 (Ubuntu)",
    }
    mock_resp.cookies = []
    mock_resp.text = "<html></html>"
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://leaky.com")

    assert len(results["server_disclosures"]) == 1
    assert "Apache/2.4.41" in results["server_disclosures"][0]


@patch('security_score.requests.get')
def test_x_powered_by_version_flagged(mock_get):
    """X-Powered-By header with a version is reported."""
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Content-Type": "text/html",
        "X-Powered-By": "PHP/8.1.2",
    }
    mock_resp.cookies = []
    mock_resp.text = "<html></html>"
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://leaky.com")

    assert len(results["server_disclosures"]) == 1
    assert "PHP/8.1.2" in results["server_disclosures"][0]


@patch('security_score.requests.get')
def test_server_without_version_not_flagged(mock_get):
    """Server header without a version is not flagged."""
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Content-Type": "text/html",
        "Server": "nginx",
    }
    mock_resp.cookies = []
    mock_resp.text = "<html></html>"
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://clean.com")

    assert len(results["server_disclosures"]) == 0


@patch('security_score.requests.get')
def test_both_server_and_powered_by_flagged(mock_get):
    """Both headers flagged when both leak versions."""
    mock_resp = MagicMock()
    mock_resp.headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/8.1",
    }
    mock_resp.cookies = []
    mock_resp.text = "<html></html>"
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://leaky.com")

    assert len(results["server_disclosures"]) == 2


def test_check_server_disclosure_standalone():
    """Unit test for check_server_disclosure method."""
    scanner = SecurityScanner()
    headers = {
        "Server": "Apache/2.4.41",
        "X-Powered-By": "Express",
    }
    disclosures = scanner.check_server_disclosure(headers)

    # Apache has a version, Express does not
    assert len(disclosures) == 1
    assert "Apache" in disclosures[0]
