import pytest
# We import SecurityScorer assuming it will live inside security_score.py
from security_score import SecurityScorer

@pytest.fixture
def scorer():
    """Provides a fresh instance of SecurityScorer for each test."""
    return SecurityScorer()

def test_perfect_score(scorer):
    """Verifies that a fully hardened site achieves a score of 100 and an A grade."""
    mock_scan_results = {
        "ssl_valid": True,
        "missing_headers": [],
        "insecure_cookies": 0
    }
    
    result = scorer.calculate_score(mock_scan_results)
    
    assert result["score"] == 100
    assert "A" in result["grade"]
    assert len(result["breakdown"]) == 0

def test_medium_risk_deductions(scorer):
    """Verifies proportional deductions for a mixture of High, Medium, and Low missing headers."""
    mock_scan_results = {
        "ssl_valid": True,
        "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"],
        "insecure_cookies": 0
    }
    # Expected deductions: 
    # CSP (HIGH: -30) + HSTS (MEDIUM: -15) + X-Content-Type-Options (LOW: -5) = -50 pts
    expected_score = 100 - (30 + 15 + 5)
    
    result = scorer.calculate_score(mock_scan_results)
    
    assert result["score"] == expected_score
    assert "C" in result["grade"]  # 50 points sits at a C grade boundary
    assert len(result["breakdown"]) == 3

def test_critical_failure_override(scorer):
    """Verifies that a broken or expired SSL certificate severely impacts the security posture."""
    mock_scan_results = {
        "ssl_valid": False,  # Critical Risk
        "missing_headers": [],
        "insecure_cookies": 0
    }
    
    result = scorer.calculate_score(mock_scan_results)
    
    # Expected deduction: SSL Invalid (CRITICAL: -50) -> Final score: 50
    assert result["score"] == 50
    assert "C" in result["grade"]
    assert any("CRITICAL: Invalid or expired SSL" in detail for detail in result["breakdown"])

def test_score_floor_limit(scorer):
    """Ensures that even if an immense amount of violations are found, the score floor never drops below 0."""
    mock_scan_results = {
        "ssl_valid": False, # -50
        "missing_headers": ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"], # -30, -30, -15
        "insecure_cookies": 10 # -45 max cap
    }
    # Total mathematical deductions = 50 + 30 + 30 + 15 + 45 = 170.
    
    result = scorer.calculate_score(mock_scan_results)
    
    assert result["score"] == 0
    assert "F" in result["grade"]
