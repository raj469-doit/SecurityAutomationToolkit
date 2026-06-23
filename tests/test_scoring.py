import pytest
from security_score import SecurityScanner

@pytest.fixture
def scanner():
    """Provides a fresh instance of SecurityScanner for each test suite run."""
    return SecurityScanner()

def test_perfect_score(scanner):
    """Verifies that a fully hardened HTTPS site achieves a score of 100 and a LOW risk rating."""
    mock_findings = {
        "target_url": "https://secure-estate.com",
        "tls_secured": True,
        "missing_headers": [],
        "cookie_violations": [],
        "discovered_forms": []
    }
    
    result = scanner.calculate_risk_posture(mock_findings)
    
    assert result["security_score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "LOW"

def test_medium_risk_deductions(scanner):
    """Verifies proportional deductions for missing headers."""
    mock_findings = {
        "target_url": "https://medium-risk.com",
        "tls_secured": True,
        # Missing Strict-Transport-Security (-15), Content-Security-Policy (-15), X-Content-Type-Options (-10)
        "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"],
        "cookie_violations": [],
        "discovered_forms": []
    }
    # Calculation: 100 - 15 - 15 - 10 = 60
    expected_score = 60
    
    result = scanner.calculate_risk_posture(mock_findings)
    
    assert result["security_score"] == expected_score
    assert result["grade"] == "C"
    assert result["risk_level"] == "MEDIUM"

def test_critical_failure_override(scanner):
    """Verifies that an unencrypted HTTP channel and a missing Secure cookie severely impact posture."""
    mock_findings = {
        "target_url": "http://vulnerable-estate.com",
        "tls_secured": False, # -25 points
        "missing_headers": ["X-Frame-Options"], # -10 points
        "cookie_violations": [
            {
                "cookie_name": "JSESSIONID",
                "issues": ["Missing 'Secure' directive"] # -20 points
            }
        ],
        "discovered_forms": []
    }
    # Calculation: 100 - 25 - 10 - 20 = 45
    expected_score = 45
    
    result = scanner.calculate_risk_posture(mock_findings)
    
    assert result["security_score"] == expected_score
    assert result["grade"] == "D"
    assert result["risk_level"] == "HIGH"

def test_score_floor_limit(scanner):
    """Ensures that even with immense amounts of violations, the score floor never drops below 0."""
    mock_findings = {
        "target_url": "http://highly-exposed.com",
        "tls_secured": False, # -25
        "missing_headers": ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"], # -15, -15, -10, -10
        "cookie_violations": [
            {
                "cookie_name": "JSESSIONID",
                "issues": ["Missing 'Secure' directive", "Missing 'HttpOnly' directive"] # -20, -10
            }
        ],
        "discovered_forms": []
    }
    # Deductions go deep into negatives, but floor clamps it to 0
    result = scanner.calculate_risk_posture(mock_findings)
    
    assert result["security_score"] == 0
    assert result["grade"] == "F"
    assert result["risk_level"] == "CRITICAL"
