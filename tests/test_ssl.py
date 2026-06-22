# File reference: tests/test_security_score.py
import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner

@patch('requests.get')
def test_header_and_tls_parsing_logic(mock_get):
    """Safely asserts scanner state configurations via mock network responses."""
    # 1. Setup simulated server response missing standard elements
    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"} # Completely empty headers
    mock_response.cookies = []
    mock_response.text = "<html><body><form method='POST' action='/login'></form></body></html>"
    mock_get.return_value = mock_response

    # 2. Trigger scan execution against an internal pseudo-domain
    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://mock-realestate-staging.internal")

    # 3. Assess business logic accuracy without hitting actual web servers
    assert results["tls_secured"] is True
    assert "Strict-Transport-Security" in results["missing_headers"]
    assert "Content-Security-Policy" in results["missing_headers"]
    assert len(results["discovered_forms"]) == 1
