import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner

@patch('requests.get')
def test_scanner_discovers_unprotected_html_input_forms(mock_get):
    """
    OWASP A03 (Injection)
    Verifies that real estate forms (such as lead generation or listing filters) 
    are accurately compiled into attack surface telemetry.
    """
    mock_html = """
    <html>
        <body>
            <form action="/api/v1/property/search" method="GET">
                <input type="text" name="zipcode">
                <input type="number" name="max_price">
            </form>
            <form action="/api/v1/agent/contact" method="POST">
                <input type="text" name="agent_id">
                <textarea name="message_body"></textarea>
            </form>
        </body>
    </html>
    """
    mock_response = MagicMock()
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = []
    mock_response.text = mock_html
    mock_get.return_value = mock_response

    scanner = SecurityScanner()
    results = scanner.scan_endpoint("https://demo-realestate.internal/search")

    assert len(results["discovered_forms"]) == 2
    
    # Validate structure of the search form
    search_form = results["discovered_forms"][0]
    assert search_form["action"] == "/api/v1/property/search"
    assert search_form["method"] == "get"
    assert "zipcode" in search_form["input_parameters"]
    assert "max_price" in search_form["input_parameters"]

    # Validate structure of the contact form
    contact_form = results["discovered_forms"][1]
    assert contact_form["action"] == "/api/v1/agent/contact"
    assert contact_form["method"] == "post"
    assert "agent_id" in contact_form["input_parameters"]
    assert "message_body" in contact_form["input_parameters"]
