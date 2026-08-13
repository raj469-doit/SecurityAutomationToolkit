"""Tests for API Security Scanner — OWASP API Security Top 10 (2023)."""

import pytest
import requests_mock

from api_scanner import APISecurityScanner


@pytest.fixture
def scanner() -> APISecurityScanner:
    """Create a scanner with short timeout for tests."""
    return APISecurityScanner(timeout=3)


class TestCORSChecks:
    """API8:2023 — CORS misconfiguration tests."""

    def test_detects_cors_wildcard(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                "https://example.com/api",
                headers={
                    "Access-Control-Allow-Origin": "*",
                },
            )
            findings = scanner.check_cors("https://example.com/api")
            assert len(findings) >= 1
            assert any(
                f["type"] == "cors_wildcard" for f in findings
            )

    def test_detects_cors_origin_reflection(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                "https://example.com/api",
                headers={
                    "Access-Control-Allow-Origin": (
                        "https://evil-attacker.com"
                    ),
                },
            )
            findings = scanner.check_cors("https://example.com/api")
            assert any(
                f["type"] == "cors_reflects_origin"
                for f in findings
            )

    def test_no_cors_findings_when_properly_configured(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                "https://example.com/api",
                headers={
                    "Access-Control-Allow-Origin": (
                        "https://app.example.com"
                    ),
                },
            )
            findings = scanner.check_cors("https://example.com/api")
            assert len(findings) == 0


class TestSensitiveHeaders:
    """API8:2023 — Sensitive header disclosure tests."""

    def test_detects_x_powered_by(
        self, scanner: APISecurityScanner,
    ) -> None:
        headers = {"X-Powered-By": "Express"}
        findings = scanner.check_sensitive_headers(headers)
        assert len(findings) == 1
        assert findings[0]["type"] == "sensitive_header_disclosure"

    def test_detects_debug_token(
        self, scanner: APISecurityScanner,
    ) -> None:
        headers = {"X-Debug-Token": "abc123"}
        findings = scanner.check_sensitive_headers(headers)
        assert len(findings) == 1

    def test_no_findings_on_clean_headers(
        self, scanner: APISecurityScanner,
    ) -> None:
        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        }
        findings = scanner.check_sensitive_headers(headers)
        assert len(findings) == 0


class TestVerboseErrors:
    """API8:2023 — Verbose error response tests."""

    def test_detects_stack_trace(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                text=(
                    "Error: Traceback (most recent call last):\n"
                    "  File '/usr/app/main.py', line 42\n"
                    "  raise ValueError('invalid')"
                ),
                status_code=500,
            )
            findings = scanner.check_verbose_errors(
                "https://example.com"
            )
            assert len(findings) >= 1

    def test_no_findings_on_clean_error(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                json={"error": "Not found"},
                status_code=404,
            )
            findings = scanner.check_verbose_errors(
                "https://example.com"
            )
            assert len(findings) == 0


class TestAPIDocumentation:
    """API8:2023 — Public documentation exposure tests."""

    def test_detects_swagger_json(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                [
                    {"status_code": 404},  # Most paths 404
                ] * 20,
            )
            m.get(
                "https://example.com/swagger.json",
                json={"swagger": "2.0", "info": {"title": "API"}},
                headers={"Content-Type": "application/json"},
            )
            findings = scanner.check_api_documentation(
                "https://example.com"
            )
            assert len(findings) == 1
            assert findings[0]["type"] == "api_docs_public"


class TestAuthentication:
    """API2:2023 — Authentication check tests."""

    def test_detects_unauthenticated_access(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                json={"users": [{"id": 1, "name": "Alice"}]},
                headers={"Content-Type": "application/json"},
            )
            findings = scanner.check_authentication(
                "https://example.com",
                endpoints=["/api/v1/users"],
            )
            assert len(findings) == 1
            assert findings[0]["type"] == "no_auth_required"

    def test_no_findings_when_auth_required(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                json={"error": "Unauthorized"},
                status_code=401,
            )
            findings = scanner.check_authentication(
                "https://example.com",
                endpoints=["/api/v1/users"],
            )
            assert len(findings) == 0


class TestRateLimiting:
    """API4:2023 — Rate limiting tests."""

    def test_detects_no_rate_limit(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                "https://example.com/api",
                json={"ok": True},
            )
            findings = scanner.check_rate_limiting(
                "https://example.com/api",
                requests_count=5,
            )
            assert len(findings) == 1
            assert findings[0]["type"] == "no_rate_limit"

    def test_no_findings_when_rate_limited(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(
                "https://example.com/api",
                [
                    {"json": {"ok": True}, "status_code": 200},
                    {"json": {"ok": True}, "status_code": 200},
                    {
                        "json": {"error": "Too many requests"},
                        "status_code": 429,
                    },
                ],
            )
            findings = scanner.check_rate_limiting(
                "https://example.com/api",
                requests_count=5,
            )
            assert len(findings) == 0


class TestAdminEndpoints:
    """API5:2023 — Admin/debug endpoint exposure tests."""

    def test_detects_exposed_actuator(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.get(
                "https://example.com/actuator/env",
                json={"profiles": ["production"]},
                status_code=200,
            )
            findings = scanner.check_admin_endpoints(
                "https://example.com"
            )
            assert len(findings) >= 1
            assert any(
                "actuator" in f["description"]
                for f in findings
            )


class TestAPIVersioning:
    """API9:2023 — Improper inventory management tests."""

    def test_detects_multiple_versions(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.get(
                "https://example.com/api/v1/health",
                json={"status": "ok"},
                status_code=200,
            )
            m.get(
                "https://example.com/api/v2/health",
                json={"status": "ok"},
                status_code=200,
            )
            findings = scanner.check_api_versioning(
                "https://example.com"
            )
            assert len(findings) == 1
            assert "multiple" in findings[0]["type"].lower()


class TestBOLAIndicators:
    """API1:2023 — BOLA indicator tests."""

    def test_detects_sequential_id_access(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.get(
                "https://example.com/api/v1/users/1",
                json={"id": 1, "name": "Alice"},
                headers={"Content-Type": "application/json"},
            )
            findings = scanner.check_bola_indicators(
                "https://example.com"
            )
            assert len(findings) >= 1
            assert any(
                f["type"] == "bola_indicator" for f in findings
            )


class TestFullScan:
    """Integration test for the full API scan."""

    def test_full_scan_returns_expected_structure(
        self, scanner: APISecurityScanner,
    ) -> None:
        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, json={"ok": True})
            results = scanner.scan_api("https://example.com")

            assert "target_url" in results
            assert "scan_type" in results
            assert results["scan_type"] == "api_security"
            assert "total_findings" in results
            assert "severity_counts" in results
            assert "Critical" in results["severity_counts"]
            assert "High" in results["severity_counts"]
            assert "Medium" in results["severity_counts"]
