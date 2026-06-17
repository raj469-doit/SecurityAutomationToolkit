import pytest
from unittest.mock import patch, Mock
import requests
from security_score import analyze_target_security

@patch('requests.get')
def test_security_score_evaluation_with_missing_headers(mock_requests_get):
    """
    PROD-READY: Mock-driven isolated unit test verifying parsing behavior 
    without initiating any external internet transport requests.
    """
    # Configure an isolated Mock object acting as an insecure web server response
    simulated_response = Mock()
    simulated_response.status_code = 200
    # Simulate an app architecture completely void of HSTS, CSP, and X-Frame
    simulated_response.headers = {
        'Content-Type': 'text/html; charset=utf-8',
        'Server': 'Production-Target-Stub'
    }
    simulated_response.cookies = []
    simulated_response.text = "<html><body><form id='test'></form></body></html>"
    
    # Tie the mock return logic into the patched module target execution area
    mock_requests_get.return_value = simulated_response

    # Execute system behavior with fake input vector tracking targets
    execution_metrics = analyze_target_security("https://internal-pipeline-test.local")

    # Assert accurate behavior based on internal metric formulas
    assert isinstance(execution_metrics, dict)
    assert "Strict-Transport-Security" in execution_metrics["missing_headers"]
    assert "Content-Security-Policy" in execution_metrics["missing_headers"]
    assert execution_metrics["score"] < 100
    
    # Confirm our network system correctly isolated the calls parameters
    mock_requests_get.assert_called_once_with(
        "https://internal-pipeline-test.local", 
        timeout=10, 
        headers={'User-Agent': 'SecurityAutomationToolkit/1.0 (Automated QA Security Pipeline)'}, 
        allow_redirects=True
    )
