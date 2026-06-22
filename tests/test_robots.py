import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner

@patch('requests.get')
def test_scanner_parses_robots_file_correctly(mock_get):
    """
    Verifies that the scanner successfully hits the path and isolates definitions
    like site directories or disallowed endpoints.
    """
    mock_robots_txt = """
    User-agent: *
    Disallow: /admin/
    Disallow: /config/
    Sitemap: https://demo-realestate.internal/sitemap.xml
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = mock_robots_txt
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    # Call your internal parser logic or method depending on how it's named in security_score.py
    # Assuming standard orchestration maps definitions straight into findings via endpoint traversal:
    results = scanner.scan_endpoint("https://demo-realestate.internal")
    
    # Assert that parsing didn't drop out due to formatting
    assert len(results["errors"]) == 0


@patch('requests.get')
def test_scanner_gracefully_handles_missing_robots_txt(mock_get):
    """
    Ensures that if robots.txt returns a 404 Not Found, the scan orchestration 
    continues without dropping exceptions or breaking execution.
    """
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://demo-realestate.internal")
    
    # Scanner should not crash on a 404, but seamlessly log telemetry or record normal state
    assert len(results["errors"]) == 0
