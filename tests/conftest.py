from unittest.mock import MagicMock, patch

import pytest

from security_score import SecurityScanner


@pytest.fixture
def scanner() -> SecurityScanner:
    """A SecurityScanner instance ready to use in tests."""
    return SecurityScanner(timeout=5)


@pytest.fixture
def mock_response() -> MagicMock:
    """
    A minimal mock requests.Response with all required
    headers present.  Override attributes as needed.
    """
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body></body></html>"
    response.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
        "X-Permitted-Cross-Domain-Policies": "none",
    }
    response.cookies = []
    return response


@pytest.fixture
def mock_https_get(mock_response: MagicMock) -> MagicMock:
    """Patch requests.get to return mock_response."""
    with patch(
        "security_score.requests.get",
        return_value=mock_response,
    ) as mock_get:
        yield mock_get
