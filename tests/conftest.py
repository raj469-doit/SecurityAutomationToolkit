# tests/conftest.py
import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner


# ---------------------------------------------------------------------------
# Shared scanner fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    """A SecurityScanner instance ready to use in tests."""
    return SecurityScanner(timeout=5)


# ---------------------------------------------------------------------------
# Shared mock HTTP response helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_response():
    """
    A minimal mock requests.Response with sane defaults.
    Tests can override attributes as needed:

        def test_something(mock_response, scanner):
            mock_response.headers = {"Content-Security-Policy": "default-src 'self'"}
            with patch("security_score.requests.get", return_value=mock_response):
                ...
    """
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body></body></html>"
    response.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
    }
    response.cookies = []
    return response


@pytest.fixture
def mock_https_get(mock_response):
    """Patch requests.get to return mock_response without hitting the network."""
    with patch("security_score.requests.get", return_value=mock_response) as mock_get:
        yield mock_get
