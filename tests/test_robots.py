"""Tests for SecurityScanner.parse_robots() (3.2)."""

from unittest.mock import MagicMock, patch

from security_score import SecurityScanner


@patch('security_score.requests.get')
def test_robots_disallow_paths_extracted(mock_get):
    """parse_robots() returns Disallow paths."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /private/\n"
        "Disallow: /tmp\n"
    )
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    result = scanner.parse_robots("https://example.com")

    assert result["disallow_paths"] == [
        "/admin", "/private/", "/tmp"
    ]


@patch('security_score.requests.get')
def test_robots_sitemap_extracted(mock_get):
    """parse_robots() returns Sitemap URLs."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = (
        "User-agent: *\n"
        "Disallow: /secret\n"
        "Sitemap: https://example.com/sitemap.xml\n"
        "Sitemap: https://example.com/sitemap2.xml\n"
    )
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    result = scanner.parse_robots("https://example.com")

    assert "/secret" in result["disallow_paths"]
    assert len(result["sitemaps"]) == 2
    assert (
        "https://example.com/sitemap.xml"
        in result["sitemaps"]
    )


@patch('security_score.requests.get')
def test_robots_missing_file_returns_empty(mock_get):
    """parse_robots() returns empty when robots.txt is 404."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "Not Found"
    mock_get.return_value = mock_resp

    scanner = SecurityScanner()
    result = scanner.parse_robots("https://example.com")

    assert result["disallow_paths"] == []
    assert result["sitemaps"] == []


@patch('security_score.requests.get')
def test_robots_network_error_returns_empty(mock_get):
    """parse_robots() handles network errors gracefully."""
    import requests as req
    mock_get.side_effect = req.exceptions.ConnectionError(
        "Connection refused"
    )

    scanner = SecurityScanner()
    result = scanner.parse_robots("https://down.com")

    assert result["disallow_paths"] == []
    assert result["sitemaps"] == []
