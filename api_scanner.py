"""
API Security Scanner — OWASP API Security Top 10 (2023)

Automated black-box API security testing covering 6 of the 10
OWASP API Security categories that are testable without authenticated
context or schema knowledge:

    API1:2023  Broken Object Level Authorization (BOLA)
    API2:2023  Broken Authentication
    API4:2023  Unrestricted Resource Consumption
    API5:2023  Broken Function Level Authorization
    API8:2023  Security Misconfiguration
    API9:2023  Improper Inventory Management

Categories NOT covered (require authenticated context or schema):
    API3:2023  Broken Object Property Level Authorization
    API6:2023  Unrestricted Access to Sensitive Business Flows
    API7:2023  Server Side Request Forgery
    API10:2023 Unsafe Consumption of APIs
"""

import logging
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("SecurityToolkit.APIScanner")

# Common API documentation/schema endpoints
API_DOC_PATHS: List[str] = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi/v3/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/.well-known/openapi.json",
]

# Common API versioned paths for inventory checks
API_VERSION_PATHS: List[str] = [
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/api/v1/health",
    "/api/v2/health",
    "/api/v1/status",
    "/api/v2/status",
]

# Common API admin/debug endpoints
API_ADMIN_PATHS: List[str] = [
    "/api/admin",
    "/api/debug",
    "/api/internal",
    "/api/config",
    "/api/env",
    "/api/metrics",
    "/api/health",
    "/api/status",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/beans",
    "/actuator/configprops",
    "/_debug",
    "/__debug__",
]

# Sensitive headers that should not appear in API responses
SENSITIVE_RESPONSE_HEADERS: List[str] = [
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Debug-Token",
    "X-Debug-Token-Link",
]

# CORS misconfigurations to check
CORS_ATTACK_ORIGINS: List[str] = [
    "https://evil-attacker.com",
    "null",
    "https://localhost",
]

# Default severity weights for API findings
API_WEIGHTS: Dict[str, int] = {
    # API1: BOLA indicators
    "api_id_enumerable": 20,
    # API2: Authentication
    "api_no_auth_required": 25,
    "api_auth_header_missing": 15,
    # API4: Resource consumption
    "api_no_rate_limit": 15,
    # API5: Function level auth
    "api_admin_exposed": 20,
    "api_debug_exposed": 20,
    # API8: Security misconfiguration
    "api_cors_wildcard": 15,
    "api_cors_reflects_origin": 20,
    "api_verbose_errors": 10,
    "api_sensitive_header_disclosure": 10,
    "api_docs_public": 10,
    # API9: Inventory management
    "api_old_version_active": 15,
    "api_undocumented_endpoint": 10,
}


class APISecurityScanner:
    """
    Scans API endpoints for OWASP API Security Top 10 (2023)
    vulnerabilities using black-box automated testing.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = "SecurityAutomationToolkit/1.0",
        weights: Optional[Dict[str, int]] = None,
    ) -> None:
        self.timeout = timeout
        self.headers: Dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "application/json",
        }
        self.weights: Dict[str, int] = weights or dict(API_WEIGHTS)

    # ── API8:2023 CORS Misconfiguration ──────────────────

    def check_cors(self, url: str) -> List[Dict[str, str]]:
        """
        Test for CORS misconfigurations by sending requests
        with various Origin headers.

        Checks for:
        - Access-Control-Allow-Origin: * (wildcard)
        - Origin reflection (echoes back any origin)
        - null origin acceptance
        """
        findings: List[Dict[str, str]] = []

        try:
            # Check for wildcard CORS
            resp = requests.get(
                url,
                headers={**self.headers, "Origin": "https://test.com"},
                timeout=self.timeout,
            )
            acao = resp.headers.get(
                "Access-Control-Allow-Origin", ""
            )
            if acao == "*":
                findings.append({
                    "type": "cors_wildcard",
                    "severity": "High",
                    "description": (
                        "Access-Control-Allow-Origin is set to '*', "
                        "allowing any origin to make cross-origin "
                        "requests to this API."
                    ),
                    "owasp_category": (
                        "API8:2023-Security Misconfiguration"
                    ),
                })

            # Check for origin reflection
            for origin in CORS_ATTACK_ORIGINS:
                resp = requests.get(
                    url,
                    headers={**self.headers, "Origin": origin},
                    timeout=self.timeout,
                )
                reflected = resp.headers.get(
                    "Access-Control-Allow-Origin", ""
                )
                if reflected == origin and origin != "":
                    findings.append({
                        "type": "cors_reflects_origin",
                        "severity": "Critical",
                        "description": (
                            f"API reflects the Origin header value "
                            f"'{origin}' in Access-Control-Allow-Origin, "
                            f"allowing attacker-controlled cross-origin "
                            f"access."
                        ),
                        "owasp_category": (
                            "API8:2023-Security Misconfiguration"
                        ),
                    })
                    break  # One reflection finding is enough

        except requests.exceptions.RequestException as e:
            logger.warning(f"CORS check failed: {e}")

        return findings

    # ── API8:2023 Sensitive Header Disclosure ─────────────

    def check_sensitive_headers(
        self, response_headers: Any,
    ) -> List[Dict[str, str]]:
        """
        Check for headers that disclose server technology,
        framework versions, or debug tokens.
        """
        findings: List[Dict[str, str]] = []

        for header in SENSITIVE_RESPONSE_HEADERS:
            value = response_headers.get(header, "")
            if value:
                findings.append({
                    "type": "sensitive_header_disclosure",
                    "severity": "Medium",
                    "description": (
                        f"Response includes {header}: {value}, "
                        f"disclosing server technology details."
                    ),
                    "owasp_category": (
                        "API8:2023-Security Misconfiguration"
                    ),
                })

        return findings

    # ── API8:2023 Verbose Error Responses ─────────────────

    def check_verbose_errors(self, url: str) -> List[Dict[str, str]]:
        """
        Send malformed requests to trigger error responses
        and check if they leak stack traces, database details,
        or internal paths.
        """
        findings: List[Dict[str, str]] = []
        error_indicators = [
            "stack trace",
            "traceback",
            "exception",
            "at line",
            "syntax error",
            "sql",
            "mysql",
            "postgresql",
            "ora-",
            "microsoft ole db",
            "internal server error",
            "/usr/",
            "/var/",
            "/home/",
            "c:\\",
            "debug",
        ]

        test_paths = [
            urljoin(url, "/api/v1/../../etc/passwd"),
            urljoin(url, "/api/v1/users/'"),
            urljoin(url, "/api/v1/null"),
        ]

        for test_url in test_paths:
            try:
                resp = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                )
                body_lower = resp.text.lower()
                for indicator in error_indicators:
                    if indicator in body_lower:
                        findings.append({
                            "type": "verbose_error",
                            "severity": "Medium",
                            "description": (
                                f"Error response from {test_url} "
                                f"contains '{indicator}', potentially "
                                f"leaking internal details."
                            ),
                            "owasp_category": (
                                "API8:2023-Security Misconfiguration"
                            ),
                        })
                        break  # One indicator per path is enough
            except requests.exceptions.RequestException:
                pass

        return findings

    # ── API8:2023 Public API Documentation ────────────────

    def check_api_documentation(
        self, url: str,
    ) -> List[Dict[str, str]]:
        """
        Check if API documentation/schema endpoints are
        publicly accessible without authentication.
        """
        findings: List[Dict[str, str]] = []
        discovered: List[str] = []

        for path in API_DOC_PATHS:
            doc_url = urljoin(url, path)
            try:
                resp = requests.get(
                    doc_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200:
                    content_type = resp.headers.get(
                        "Content-Type", ""
                    ).lower()
                    is_json = "json" in content_type
                    is_html = "html" in content_type
                    has_swagger = (
                        "swagger" in resp.text.lower()
                        or "openapi" in resp.text.lower()
                    )

                    if is_json or has_swagger or (
                        is_html and has_swagger
                    ):
                        discovered.append(path)
            except requests.exceptions.RequestException:
                pass

        if discovered:
            findings.append({
                "type": "api_docs_public",
                "severity": "Medium",
                "description": (
                    f"API documentation publicly accessible at: "
                    f"{', '.join(discovered)}. May expose endpoint "
                    f"inventory, parameters, and authentication "
                    f"requirements to attackers."
                ),
                "owasp_category": (
                    "API8:2023-Security Misconfiguration"
                ),
            })

        return findings

    # ── API2:2023 Authentication Checks ───────────────────

    def check_authentication(
        self, url: str, endpoints: Optional[List[str]] = None,
    ) -> List[Dict[str, str]]:
        """
        Check if API endpoints respond with data when no
        authentication is provided. Tests common REST
        endpoints that should require auth.
        """
        findings: List[Dict[str, str]] = []
        test_endpoints = endpoints or [
            "/api/v1/users",
            "/api/v1/accounts",
            "/api/v1/orders",
            "/api/v1/profile",
            "/api/v1/settings",
            "/api/users",
            "/api/accounts",
            "/api/me",
        ]

        for endpoint in test_endpoints:
            ep_url = urljoin(url, endpoint)
            try:
                # Request without any auth headers
                no_auth_headers = {
                    "User-Agent": self.headers["User-Agent"],
                    "Accept": "application/json",
                }
                resp = requests.get(
                    ep_url,
                    headers=no_auth_headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                # 200 with JSON body = likely no auth required
                if resp.status_code == 200:
                    content_type = resp.headers.get(
                        "Content-Type", ""
                    ).lower()
                    if "json" in content_type:
                        findings.append({
                            "type": "no_auth_required",
                            "severity": "Critical",
                            "description": (
                                f"Endpoint {endpoint} returns data "
                                f"(HTTP 200 + JSON) without any "
                                f"authentication headers."
                            ),
                            "owasp_category": (
                                "API2:2023-Broken Authentication"
                            ),
                        })

            except requests.exceptions.RequestException:
                pass

        return findings

    # ── API4:2023 Rate Limiting ───────────────────────────

    def check_rate_limiting(
        self, url: str, requests_count: int = 20,
    ) -> List[Dict[str, str]]:
        """
        Send rapid sequential requests to check if rate
        limiting is enforced. Looks for 429 responses or
        rate-limit headers.
        """
        findings: List[Dict[str, str]] = []
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-Rate-Limit-Limit",
            "RateLimit-Limit",
            "Retry-After",
        ]

        got_429 = False
        has_rate_headers = False

        for i in range(requests_count):
            try:
                resp = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                )
                if resp.status_code == 429:
                    got_429 = True
                    break
                for rh in rate_limit_headers:
                    if rh in resp.headers:
                        has_rate_headers = True
                        break
                if has_rate_headers:
                    break
            except requests.exceptions.RequestException:
                break

        if not got_429 and not has_rate_headers:
            findings.append({
                "type": "no_rate_limit",
                "severity": "High",
                "description": (
                    f"No rate limiting detected after "
                    f"{requests_count} rapid requests. No 429 "
                    f"responses or rate-limit headers observed."
                ),
                "owasp_category": (
                    "API4:2023-Unrestricted Resource Consumption"
                ),
            })

        return findings

    # ── API5:2023 Admin/Debug Endpoint Exposure ───────────

    def check_admin_endpoints(
        self, url: str,
    ) -> List[Dict[str, str]]:
        """
        Check for exposed administrative, debug, and internal
        API endpoints that should not be publicly accessible.
        """
        findings: List[Dict[str, str]] = []

        for path in API_ADMIN_PATHS:
            admin_url = urljoin(url, path)
            try:
                resp = requests.get(
                    admin_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200:
                    findings.append({
                        "type": "admin_endpoint_exposed",
                        "severity": "High",
                        "description": (
                            f"Administrative/debug endpoint "
                            f"accessible at {path} (HTTP 200)."
                        ),
                        "owasp_category": (
                            "API5:2023-Broken Function Level "
                            "Authorization"
                        ),
                    })
            except requests.exceptions.RequestException:
                pass

        return findings

    # ── API9:2023 Version Discovery ───────────────────────

    def check_api_versioning(
        self, url: str,
    ) -> List[Dict[str, str]]:
        """
        Check for multiple active API versions, which may
        indicate deprecated endpoints still serving traffic.
        """
        findings: List[Dict[str, str]] = []
        active_versions: List[str] = []

        for path in API_VERSION_PATHS:
            ver_url = urljoin(url, path)
            try:
                resp = requests.get(
                    ver_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (200, 301, 302):
                    active_versions.append(path)
            except requests.exceptions.RequestException:
                pass

        if len(active_versions) > 1:
            # Extract unique version numbers
            versions = set()
            for v in active_versions:
                match = re.search(r"v(\d+)", v)
                if match:
                    versions.add(match.group(1))

            if len(versions) > 1:
                findings.append({
                    "type": "multiple_api_versions",
                    "severity": "High",
                    "description": (
                        f"Multiple API versions active: "
                        f"{', '.join(sorted(versions))}. "
                        f"Older versions may lack security "
                        f"patches applied to current version."
                    ),
                    "owasp_category": (
                        "API9:2023-Improper Inventory Management"
                    ),
                })

        return findings

    # ── API1:2023 BOLA Indicators ─────────────────────────

    def check_bola_indicators(
        self, url: str,
    ) -> List[Dict[str, str]]:
        """
        Check for indicators of Broken Object Level
        Authorization by testing sequential ID patterns
        in common API endpoints.

        Note: This is a heuristic check. True BOLA testing
        requires authenticated context with multiple user
        sessions, which is handled in manual verification.
        """
        findings: List[Dict[str, str]] = []
        id_endpoints = [
            "/api/v1/users/{id}",
            "/api/v1/orders/{id}",
            "/api/v1/accounts/{id}",
            "/api/users/{id}",
            "/api/orders/{id}",
        ]

        for endpoint_template in id_endpoints:
            for test_id in ["1", "2", "100", "admin"]:
                endpoint = endpoint_template.replace(
                    "{id}", test_id
                )
                ep_url = urljoin(url, endpoint)
                try:
                    resp = requests.get(
                        ep_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    if resp.status_code == 200:
                        content_type = resp.headers.get(
                            "Content-Type", ""
                        ).lower()
                        if "json" in content_type:
                            findings.append({
                                "type": "bola_indicator",
                                "severity": "Critical",
                                "description": (
                                    f"Endpoint {endpoint} returns "
                                    f"data (HTTP 200 + JSON) with "
                                    f"sequential ID '{test_id}' "
                                    f"without authentication. "
                                    f"Potential BOLA vulnerability."
                                ),
                                "owasp_category": (
                                    "API1:2023-Broken Object Level "
                                    "Authorization"
                                ),
                            })
                            break  # One finding per template
                except requests.exceptions.RequestException:
                    pass

        return findings

    # ── Main scan method ──────────────────────────────────

    def scan_api(self, url: str) -> Dict[str, Any]:
        """
        Run all API security checks against the target URL.

        Returns a findings dict with categorized results.
        """
        logger.info(f"API Security Scan: {url}")

        results: Dict[str, Any] = {
            "target_url": url,
            "scan_type": "api_security",
            "owasp_framework": "OWASP API Security Top 10 (2023)",
            "cors_findings": [],
            "sensitive_headers": [],
            "verbose_errors": [],
            "api_documentation": [],
            "authentication_findings": [],
            "rate_limiting": [],
            "admin_endpoints": [],
            "api_versioning": [],
            "bola_indicators": [],
            "errors": [],
        }

        try:
            # Initial request to get response headers
            resp = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
            )

            # API8: CORS
            logger.info("Checking CORS configuration...")
            results["cors_findings"] = self.check_cors(url)

            # API8: Sensitive headers
            logger.info("Checking sensitive headers...")
            results["sensitive_headers"] = (
                self.check_sensitive_headers(resp.headers)
            )

            # API8: Verbose errors
            logger.info("Checking verbose error responses...")
            results["verbose_errors"] = (
                self.check_verbose_errors(url)
            )

            # API8: Public documentation
            logger.info("Checking API documentation exposure...")
            results["api_documentation"] = (
                self.check_api_documentation(url)
            )

            # API2: Authentication
            logger.info("Checking authentication requirements...")
            results["authentication_findings"] = (
                self.check_authentication(url)
            )

            # API4: Rate limiting
            logger.info("Checking rate limiting...")
            results["rate_limiting"] = (
                self.check_rate_limiting(url)
            )

            # API5: Admin endpoints
            logger.info("Checking admin/debug endpoints...")
            results["admin_endpoints"] = (
                self.check_admin_endpoints(url)
            )

            # API9: Version inventory
            logger.info("Checking API versioning...")
            results["api_versioning"] = (
                self.check_api_versioning(url)
            )

            # API1: BOLA indicators
            logger.info("Checking BOLA indicators...")
            results["bola_indicators"] = (
                self.check_bola_indicators(url)
            )

        except requests.exceptions.RequestException as e:
            logger.error(f"API scan failed: {e}")
            results["errors"].append(
                f"Scan failed: {type(e).__name__}: {str(e)}"
            )

        # Aggregate all findings
        all_findings: List[Dict[str, str]] = []
        for key in [
            "cors_findings", "sensitive_headers",
            "verbose_errors", "api_documentation",
            "authentication_findings", "rate_limiting",
            "admin_endpoints", "api_versioning",
            "bola_indicators",
        ]:
            all_findings.extend(results[key])

        results["total_findings"] = len(all_findings)
        results["all_findings"] = all_findings

        # Count by severity
        results["severity_counts"] = {
            "Critical": sum(
                1 for f in all_findings
                if f["severity"] == "Critical"
            ),
            "High": sum(
                1 for f in all_findings
                if f["severity"] == "High"
            ),
            "Medium": sum(
                1 for f in all_findings
                if f["severity"] == "Medium"
            ),
        }

        logger.info(
            f"API scan complete. "
            f"{results['total_findings']} findings."
        )

        return results
