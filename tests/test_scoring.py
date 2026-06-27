import pytest

from security_score import SecurityScanner


@pytest.fixture
def scanner():
    """Provides a fresh SecurityScanner for each test."""
    return SecurityScanner()


def test_perfect_score(scanner):
    """A fully hardened HTTPS site scores 100 with a LOW risk rating."""
    findings = {
        "target_url": "https://secure.com",
        "tls_secured": True,
        "missing_headers": [],
        "cookie_violations": [],
        "discovered_forms": [],
    }
    result = scanner.calculate_risk_posture(findings)

    assert result["security_score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "LOW"


def test_medium_risk_deductions(scanner):
    """Missing headers cause proportional point deductions."""
    findings = {
        "target_url": "https://medium-risk.com",
        "tls_secured": True,
        # -15 (HSTS), -15 (CSP), -10 (X-Content-Type-Options) = 60
        "missing_headers": [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
        ],
        "cookie_violations": [],
        "discovered_forms": [],
    }
    result = scanner.calculate_risk_posture(findings)

    assert result["security_score"] == 60
    assert result["grade"] == "C"
    assert result["risk_level"] == "MEDIUM"


def test_critical_failure_override(scanner):
    """HTTP + missing header + insecure cookie produces grade D."""
    findings = {
        "target_url": "http://vulnerable.com",
        "tls_secured": False,  # -25
        "missing_headers": ["X-Frame-Options"],  # -10
        "cookie_violations": [
            {
                "cookie_name": "JSESSIONID",
                "issues": ["Missing 'Secure' directive"],  # -20
            }
        ],
        "discovered_forms": [],
    }
    # 100 - 25 - 10 - 20 = 45
    result = scanner.calculate_risk_posture(findings)

    assert result["security_score"] == 45
    assert result["grade"] == "D"
    assert result["risk_level"] == "HIGH"


def test_score_floor_limit(scanner):
    """Score never drops below 0 regardless of total deductions."""
    findings = {
        "target_url": "http://highly-exposed.com",
        "tls_secured": False,  # -25
        "missing_headers": [
            "Strict-Transport-Security",  # -15
            "Content-Security-Policy",  # -15
            "X-Frame-Options",  # -10
            "X-Content-Type-Options",  # -10
        ],
        "cookie_violations": [
            {
                "cookie_name": "JSESSIONID",
                "issues": [
                    "Missing 'Secure' directive",  # -20
                    "Missing 'HttpOnly' directive",  # -10
                ],
            }
        ],
        "discovered_forms": [],
    }
    result = scanner.calculate_risk_posture(findings)

    assert result["security_score"] == 0
    assert result["grade"] == "F"
    assert result["risk_level"] == "CRITICAL"
