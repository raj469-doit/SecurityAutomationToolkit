"""Tests for A01:2021 Broken Access Control checks."""
import pytest
from unittest.mock import patch, MagicMock
from security_score import SecurityScanner


@pytest.fixture
def scanner():
    return SecurityScanner(timeout=5)


class TestSensitiveFiles:
    """Tests for check_sensitive_files method."""

    @patch("security_score.requests.get")
    def test_detects_exposed_env_file(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_sensitive_files("https://example.com")

        # Assert
        exposed_paths = [r["path"] for r in results]
        assert "/.env" in exposed_paths
        assert results[0]["severity"] == "Critical"
        assert results[0]["access_type"] == "direct"

    @patch("security_score.requests.get")
    def test_ignores_404_responses(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_sensitive_files("https://example.com")

        # Assert
        assert len(results) == 0

    @patch("security_score.requests.get")
    def test_detects_redirect_as_medium(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_response.headers = {"Location": "/login"}
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_sensitive_files("https://example.com")

        # Assert
        assert len(results) > 0
        assert results[0]["severity"] == "Medium"
        assert results[0]["access_type"] == "redirect"

    @patch("security_score.requests.get")
    def test_handles_timeout_gracefully(self, mock_get, scanner):
        # Arrange
        import requests
        mock_get.side_effect = requests.exceptions.Timeout

        # Act
        results = scanner.check_sensitive_files("https://example.com")

        # Assert
        assert len(results) == 0


class TestAdminPaths:
    """Tests for check_admin_paths method."""

    @patch("security_score.requests.get")
    def test_detects_exposed_admin_panel(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_admin_paths("https://example.com")

        # Assert
        exposed_paths = [r["path"] for r in results]
        assert "/admin" in exposed_paths
        assert results[0]["severity"] == "High"

    @patch("security_score.requests.get")
    def test_redirect_admin_is_low_severity(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "/admin/login"}
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_admin_paths("https://example.com")

        # Assert
        assert results[0]["severity"] == "Low"
        assert results[0]["access_type"] == "redirect"


class TestDirectoryListing:
    """Tests for check_directory_listing method."""

    @patch("security_score.requests.get")
    def test_detects_directory_listing(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Index of /uploads/</title></html>"
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_directory_listing("https://example.com")

        # Assert
        assert len(results) > 0
        assert results[0]["severity"] == "Medium"
        assert results[0]["signature_matched"] == "Index of /"

    @patch("security_score.requests.get")
    def test_ignores_normal_pages(self, mock_get, scanner):
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><title>Welcome to our site</title></html>"
        mock_get.return_value = mock_response

        # Act
        results = scanner.check_directory_listing("https://example.com")

        # Assert
        assert len(results) == 0


class TestAccessControlScoring:
    """Tests for A01 scoring deductions."""

    def test_sensitive_file_deducts_25_points(self, scanner):
        # Arrange
        findings = {
            "tls_secured": True,
            "missing_headers": [],
            "cookie_violations": [],
            "server_disclosures": [],
            "exposed_sensitive_files": [{
                "path": "/.env",
                "status_code": 200,
                "severity": "Critical",
                "access_type": "direct",
            }],
            "exposed_admin_paths": [],
            "directory_listings": [],
        }

        # Act
        result = scanner.calculate_risk_posture(findings)

        # Assert
        assert result["security_score"] == 75

    def test_admin_path_deducts_15_points(self, scanner):
        # Arrange
        findings = {
            "tls_secured": True,
            "missing_headers": [],
            "cookie_violations": [],
            "server_disclosures": [],
            "exposed_sensitive_files": [],
            "exposed_admin_paths": [{
                "path": "/admin",
                "status_code": 200,
                "severity": "High",
                "access_type": "direct",
            }],
            "directory_listings": [],
        }

        # Act
        result = scanner.calculate_risk_posture(findings)

        # Assert
        assert result["security_score"] == 85