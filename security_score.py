"""
Security Automation Toolkit - CLI scanner and scoring engine.

Scans a website for common security issues (missing headers, cookie flags,
HTTPS, robots.txt, server version disclosure), scores the result, and
writes HTML + Markdown reports.
"""

import argparse
import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import yaml
from bs4 import BeautifulSoup

from generate_report import ComplianceReporter

# ── A01:2021 Broken Access Control probe paths ───────────

SENSITIVE_FILES: List[str] = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/application.properties",
    "/appsettings.json",
    "/web.config",
    "/settings.py",
    "/backup.sql",
    "/dump.sql",
]

ADMIN_PATHS: List[str] = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/dbadmin",
    "/api/docs",
    "/swagger",
    "/graphql",
    "/phpinfo.php",
]

DIRECTORY_LISTING_PATHS: List[str] = [
    "/",
    "/images/",
    "/uploads/",
    "/assets/",
    "/static/",
    "/logs/",
    "/tmp/",
]

DIRECTORY_LISTING_SIGNATURES: List[str] = [
    "Index of /",
    "Directory listing for",
    "[To Parent Directory]",
    "<title>Directory",
]

# Set up logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("SecurityToolkit.Engine")

# Default severity weights — used when no config file is provided.
# These match config/config.example.yaml.
DEFAULT_WEIGHTS: Dict[str, int] = {
    "no_https": 25,
    "Strict-Transport-Security": 15,
    "Content-Security-Policy": 15,
    "X-Frame-Options": 10,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5,
    "X-Permitted-Cross-Domain-Policies": 5,
    "cookie_missing_secure": 20,
    "cookie_missing_httponly": 10,
    "server_version_disclosure": 10,
    # A01:2021 Broken Access Control
    "sensitive_file_exposed": 25,
    "sensitive_file_redirect": 10,
    "admin_path_exposed": 15,
    "admin_path_redirect": 5,
    "directory_listing": 5,
}

# Regex for version numbers like Apache/2.4.41 or PHP/8.1.2
_VERSION_RE = re.compile(r"/\d+[\d.]*")


def load_config(
    config_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Load scanner config from a YAML file. Falls back to built-in
    defaults for any missing keys.

    Returns a dict with 'scan_settings' and 'severity_weights'.
    """
    defaults: Dict[str, Any] = {
        "scan_settings": {
            "default_timeout": 10,
            "user_agent": "SecurityAutomationToolkit/1.0",
            "allow_redirects": True,
        },
        "severity_weights": dict(DEFAULT_WEIGHTS),
    }

    if not config_path or not os.path.exists(config_path):
        return defaults

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(
            f"Could not read config file: {e}. Using defaults."
        )
        return defaults

    # Merge user values over defaults
    if "scan_settings" in user_cfg:
        defaults["scan_settings"].update(
            user_cfg["scan_settings"]
        )
    if "severity_weights" in user_cfg:
        defaults["severity_weights"].update(
            user_cfg["severity_weights"]
        )

    return defaults


class SecurityScanner:
    """
    Scans a website for security issues: headers, cookies, HTTPS,
    forms, robots.txt, and server version disclosure.
    Calculates a 0-100 score and letter grade.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = "SecurityAutomationToolkit/1.0",
        weights: Optional[Dict[str, int]] = None,
    ) -> None:
        """Set up the HTTP session and scoring weights."""
        self.timeout = timeout
        self.headers: Dict[str, str] = {"User-Agent": user_agent}
        self.weights: Dict[str, int] = (
            weights or dict(DEFAULT_WEIGHTS)
        )

    # ── robots.txt parsing (3.2) ──────────────────────────

    def parse_robots(self, url: str) -> Dict[str, Any]:
        """
        Fetch /robots.txt from the target and extract Disallow
        paths and Sitemap URLs.

        Returns a dict with 'disallow_paths' and 'sitemaps' lists.
        """
        result: Dict[str, Any] = {
            "disallow_paths": [],
            "sitemaps": [],
        }
        robots_url = urljoin(url, "/robots.txt")

        try:
            resp = requests.get(
                robots_url,
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return result

            for line in resp.text.splitlines():
                stripped = line.strip()
                lower = stripped.lower()
                if lower.startswith("disallow:"):
                    path = stripped.split(":", 1)[1].strip()
                    if path:
                        result["disallow_paths"].append(path)
                elif lower.startswith("sitemap:"):
                    sitemap = stripped.split(":", 1)[1].strip()
                    if sitemap:
                        result["sitemaps"].append(sitemap)

        except requests.exceptions.RequestException as e:
            logger.warning(
                f"Could not fetch robots.txt: {e}"
            )

        return result

    # ── Server version disclosure (3.4) ───────────────────

    def check_server_disclosure(
        self, response_headers: Any,
    ) -> List[str]:
        """
        Check Server and X-Powered-By headers for version
        numbers that leak infrastructure details.

        Returns a list of disclosure strings, e.g.
        ["Server: Apache/2.4.41", "X-Powered-By: PHP/8.1"].
        """
        disclosures: List[str] = []
        for hdr in ("Server", "X-Powered-By"):
            value = response_headers.get(hdr, "")
            if value and _VERSION_RE.search(value):
                disclosures.append(f"{hdr}: {value}")
        return disclosures

    # ── Scoring ───────────────────────────────────────────

    # ── A01:2021 Broken Access Control ────────────────────

    def check_sensitive_files(self, url: str) -> List[Dict[str, Any]]:
        """
        Probe for exposed sensitive files that could leak
        credentials, configuration, or source code.
        """
        results: List[Dict[str, Any]] = []
        for path in SENSITIVE_FILES:
            probe_url = urljoin(url, path)
            try:
                resp = requests.get(
                    probe_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200:
                    results.append({
                        "path": path,
                        "status_code": 200,
                        "severity": "Critical",
                        "access_type": "direct",
                    })
                elif resp.status_code in (301, 302):
                    location = resp.headers.get("Location", "unknown")
                    results.append({
                        "path": path,
                        "status_code": resp.status_code,
                        "severity": "Medium",
                        "access_type": "redirect",
                        "redirect_to": location,
                    })
            except requests.exceptions.RequestException:
                continue
        return results

    def check_admin_paths(self, url: str) -> List[Dict[str, Any]]:
        """
        Probe for exposed admin panels and API documentation
        endpoints that expand the attack surface.
        """
        results: List[Dict[str, Any]] = []
        for path in ADMIN_PATHS:
            probe_url = urljoin(url, path)
            try:
                resp = requests.get(
                    probe_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if resp.status_code == 200:
                    results.append({
                        "path": path,
                        "status_code": 200,
                        "severity": "High",
                        "access_type": "direct",
                    })
                elif resp.status_code in (301, 302):
                    location = resp.headers.get("Location", "unknown")
                    results.append({
                        "path": path,
                        "status_code": resp.status_code,
                        "severity": "Low",
                        "access_type": "redirect",
                        "redirect_to": location,
                    })
            except requests.exceptions.RequestException:
                continue
        return results

    def check_directory_listing(self, url: str) -> List[Dict[str, Any]]:
        """
        Check common directories for enabled directory listing,
        which exposes file structure to attackers.
        """
        results: List[Dict[str, Any]] = []
        for path in DIRECTORY_LISTING_PATHS:
            probe_url = urljoin(url, path)
            try:
                resp = requests.get(
                    probe_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                if resp.status_code == 200:
                    body = resp.text[:2000]  # only check first 2KB
                    for signature in DIRECTORY_LISTING_SIGNATURES:
                        if signature.lower() in body.lower():
                            results.append({
                                "path": path,
                                "status_code": 200,
                                "severity": "Medium",
                                "signature_matched": signature,
                            })
                            break
            except requests.exceptions.RequestException:
                continue
        return results

    def calculate_risk_posture(
        self, findings: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Deduct points for each issue found and assign a grade
        and risk level.  Returns the updated findings dict.
        """
        score: int = 100
        w = self.weights

        # Deduct for missing HTTPS (OWASP A04:2021)
        if not findings["tls_secured"]:
            pts = w.get("no_https", 25)
            score -= pts
            logger.warning(
                f"Deducting {pts} points: "
                f"site does not use HTTPS."
            )

        # Deduct for missing security headers (OWASP A05:2021)
        for header in findings["missing_headers"]:
            pts = w.get(header, 0)
            if pts:
                score -= pts
                logger.warning(
                    f"Deducting {pts} points: "
                    f"missing header '{header}'."
                )

        # Deduct for cookie flag violations
        for violation in findings["cookie_violations"]:
            for issue in violation["issues"]:
                if "Secure" in issue:
                    pts = w.get("cookie_missing_secure", 20)
                    score -= pts
                    logger.warning(
                        f"Deducting {pts} points: cookie "
                        f"'{violation['cookie_name']}' "
                        f"is missing the Secure flag."
                    )
                elif "HttpOnly" in issue:
                    pts = w.get(
                        "cookie_missing_httponly", 10
                    )
                    score -= pts
                    logger.warning(
                        f"Deducting {pts} points: cookie "
                        f"'{violation['cookie_name']}' "
                        f"is missing the HttpOnly flag."
                    )

        # Deduct for server version disclosure (3.4)
        for disc in findings.get("server_disclosures", []):
            pts = w.get("server_version_disclosure", 10)
            score -= pts
            logger.warning(
                f"Deducting {pts} points: "
                f"version disclosure in '{disc}'."
            )

        # Deduct for A01:2021 Broken Access Control
        for item in findings.get("exposed_sensitive_files", []):
            if item["access_type"] == "direct":
                pts = w.get("sensitive_file_exposed", 25)
            else:
                pts = w.get("sensitive_file_redirect", 10)
            score -= pts
            logger.warning(
                f"Deducting {pts} points: "
                f"sensitive file '{item['path']}' "
                f"accessible ({item['access_type']})."
            )

        for item in findings.get("exposed_admin_paths", []):
            if item["access_type"] == "direct":
                pts = w.get("admin_path_exposed", 15)
            else:
                pts = w.get("admin_path_redirect", 5)
            score -= pts
            logger.warning(
                f"Deducting {pts} points: "
                f"admin path '{item['path']}' "
                f"accessible ({item['access_type']})."
            )

        for item in findings.get("directory_listings", []):
            pts = w.get("directory_listing", 5)
            score -= pts
            logger.warning(
                f"Deducting {pts} points: "
                f"directory listing at '{item['path']}'."
            )
        # Clamp to 0-100
        score = max(0, min(100, score))
        findings["security_score"] = score

        # Assign grade and risk level
        if score >= 90:
            findings["grade"] = "A"
            findings["risk_level"] = "LOW"
        elif score >= 75:
            findings["grade"] = "B"
            findings["risk_level"] = "LOW"
        elif score >= 60:
            findings["grade"] = "C"
            findings["risk_level"] = "MEDIUM"
        elif score >= 45:
            findings["grade"] = "D"
            findings["risk_level"] = "HIGH"
        else:
            findings["grade"] = "F"
            findings["risk_level"] = "CRITICAL"

        logger.info(
            f"Score: {score}, Grade: {findings['grade']}, "
            f"Risk: {findings['risk_level']}"
        )
        return findings

    # ── Main scan ─────────────────────────────────────────

    def scan_endpoint(self, url: str) -> Dict[str, Any]:
        """
        Scan a single URL and return a findings dict.
        On network errors, returns a score of 0 / grade F.
        """
        logger.info(f"Scanning: {url}")

        findings: Dict[str, Any] = {
            "target_url": url,
            "tls_secured": False,
            "security_score": 100,
            "grade": "A",
            "risk_level": "LOW",
            "missing_headers": [],
            "cookie_violations": [],
            "discovered_forms": [],
            "robots": {"disallow_paths": [], "sitemaps": []},
            "server_disclosures": [],
            "exposed_sensitive_files": [],    # A01:2021
            "exposed_admin_paths": [],        # A01:2021
            "directory_listings": [],         # A01:2021
            "errors": [],
        }

        parsed = urlparse(url)
        if parsed.scheme == "https":
            findings["tls_secured"] = True

        try:
            response = requests.get(
                url, headers=self.headers,
                timeout=self.timeout,
                allow_redirects=True,
            )

            # Check for required security headers (3.1)
            required_headers: List[str] = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
                "X-Permitted-Cross-Domain-Policies",
            ]
            for header in required_headers:
                if header not in response.headers:
                    findings["missing_headers"].append(header)

            # Check cookie flags
            for cookie in response.cookies:
                issues: List[str] = []
                if not cookie.secure:
                    issues.append(
                        "Missing 'Secure' directive"
                    )
                is_httponly = (
                    cookie.has_nonstandard_attr('HttpOnly')
                    or cookie.has_nonstandard_attr('httponly')
                )
                if not is_httponly:
                    issues.append(
                        "Missing 'HttpOnly' directive"
                    )
                if issues:
                    findings["cookie_violations"].append({
                        "cookie_name": cookie.name,
                        "issues": issues,
                    })

            # Discover forms on the page
            soup = BeautifulSoup(
                response.text, 'html.parser'
            )
            for index, form in enumerate(
                soup.find_all('form')
            ):
                inputs: List[str] = [
                    str(inp.get('name'))
                    for inp in form.find_all(
                        ['input', 'textarea']
                    )
                    if inp.get('name')
                ]
                action = form.get('action', '') or ''
                method = form.get('method', 'get') or 'get'
                findings["discovered_forms"].append({
                    "form_index": index,
                    "action": str(action),
                    "method": str(method).lower(),
                    "input_parameters": inputs,
                })

            # Server version disclosure (3.4)
            findings["server_disclosures"] = (
                self.check_server_disclosure(response.headers)
            )

        except requests.exceptions.Timeout:
            logger.error(f"Request timed out for: {url}")
            findings["errors"].append("Request timed out")
            findings["security_score"] = 0
            findings["grade"] = "F"
            findings["risk_level"] = "CRITICAL"
            return findings

        except requests.exceptions.RequestException as e:
            logger.error(
                f"Network error on {url}: {str(e)}"
            )
            findings["errors"].append(
                f"Connection failed: {type(e).__name__}"
            )
            findings["security_score"] = 0
            findings["grade"] = "F"
            findings["risk_level"] = "CRITICAL"
            return findings

        # A01:2021 Broken Access Control checks
        findings["exposed_sensitive_files"] = (
                self.check_sensitive_files(url)
            )
        findings["exposed_admin_paths"] = (
                self.check_admin_paths(url)
            )
        findings["directory_listings"] = (
                self.check_directory_listing(url)
            )

        # Parse robots.txt (3.2)
        findings["robots"] = self.parse_robots(url)

        return self.calculate_risk_posture(findings)


def _map_findings_to_vulnerabilities(
    scan_results: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert raw scan findings into the vulnerability format
    expected by ComplianceReporter.
    """
    vulnerabilities: List[Dict[str, str]] = []

    if not scan_results["tls_secured"]:
        vulnerabilities.append({
            "owasp_category": (
                "A04:2021-Cryptographic Failures"
            ),
            "severity": "High",
            "description": (
                "Site is served over plain HTTP "
                "instead of HTTPS."
            ),
            "remediation": (
                "Redirect all traffic to HTTPS "
                "and enable HSTS."
            ),
        })

    high_risk = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
    ]
    medium_risk = [
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]
    for header in scan_results["missing_headers"]:
        if header in high_risk:
            sev = "High"
        elif header in medium_risk:
            sev = "Medium"
        else:
            sev = "Low"
        vulnerabilities.append({
            "owasp_category": (
                "A05:2021-Security Misconfiguration"
            ),
            "severity": sev,
            "description": (
                f"Missing security header: '{header}'."
            ),
            "remediation": (
                f"Configure your server to send "
                f"the '{header}' header."
            ),
        })

    for cv in scan_results["cookie_violations"]:
        for issue in cv["issues"]:
            sev = "High" if "Secure" in issue else "Medium"
            flag = issue.replace(
                "Missing '", ""
            ).replace("' directive", "")
            vulnerabilities.append({
                "owasp_category": (
                    "A05:2021-Security Misconfiguration"
                ),
                "severity": sev,
                "description": (
                    f"Cookie '{cv['cookie_name']}' is "
                    f"missing the {flag} flag."
                ),
                "remediation": (
                    f"Set the {flag} flag on "
                    f"cookie '{cv['cookie_name']}'."
                ),
            })

    # Server version disclosure (3.4)
    for disc in scan_results.get("server_disclosures", []):
        vulnerabilities.append({
            "owasp_category": (
                "A06:2021-Vulnerable Components"
            ),
            "severity": "Medium",
            "description": (
                f"Server version disclosed: {disc}."
            ),
            "remediation": (
                "Remove or suppress version information "
                "from server response headers."
            ),
        })

    # A01:2021 Broken Access Control
    for item in scan_results.get("exposed_sensitive_files", []):
        sev = "Critical" if item["access_type"] == "direct" else "Medium"
        desc = (
            f"Sensitive file '{item['path']}' is directly accessible."
            if item["access_type"] == "direct"
            else f"Sensitive file '{item['path']}' redirects to "
                 f"'{item.get('redirect_to', 'unknown')}'."
        )
        vulnerabilities.append({
            "owasp_category": "A01:2021-Broken Access Control",
            "severity": sev,
            "description": desc,
            "remediation": (
                f"Block public access to '{item['path']}' "
                f"via server configuration or .htaccess rules."
            ),
        })

    for item in scan_results.get("exposed_admin_paths", []):
        sev = "High" if item["access_type"] == "direct" else "Low"
        desc = (
            f"Admin panel '{item['path']}' is publicly accessible."
            if item["access_type"] == "direct"
            else f"Admin panel '{item['path']}' exists "
                 f"(redirects to '{item.get('redirect_to', 'unknown')}')."
        )
        vulnerabilities.append({
            "owasp_category": "A01:2021-Broken Access Control",
            "severity": sev,
            "description": desc,
            "remediation": (
                f"Restrict access to '{item['path']}' "
                f"using IP allowlists or VPN requirements."
            ),
        })

    for item in scan_results.get("directory_listings", []):
        vulnerabilities.append({
            "owasp_category": "A01:2021-Broken Access Control",
            "severity": "Medium",
            "description": (
                f"Directory listing enabled at '{item['path']}' "
                f"(matched signature: '{item['signature_matched']}')."
            ),
            "remediation": (
                "Disable directory listing in your web server "
                "configuration (e.g., 'Options -Indexes' in Apache)."
            ),
        })
    return {
        "target": scan_results["target_url"],
        "final_score": scan_results["security_score"],
        "vulnerabilities": vulnerabilities,
    }


def _get_domain_filename(url: str) -> str:
    """
    Build a filename for the JSON baseline from the target
    domain, e.g. 'latest_scan_example_com.json'.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path
        clean_name = (
            hostname.replace("www.", "")
            .replace(".", "_")
            .replace(":", "_")
        )
        return f"latest_scan_{clean_name}.json"
    except Exception:
        return "latest_scan_fallback.json"


def main() -> None:
    """Run a scan against a URL and save reports."""
    parser = argparse.ArgumentParser(
        description="Website security scanner"
    )
    parser.add_argument(
        "--url", required=True, help="URL to scan"
    )
    parser.add_argument(
        "--output-dir", default="outputs",
        help="Directory for report files (default: outputs/)",
    )
    parser.add_argument(
        "--config",
        help="Path to a YAML config file (optional)",
    )
    args = parser.parse_args()

    # Load config (falls back to defaults if no file given)
    cfg = load_config(args.config)
    settings = cfg["scan_settings"]
    weights = cfg["severity_weights"]

    os.makedirs(args.output_dir, exist_ok=True)

    baseline_filename = _get_domain_filename(args.url)
    baseline_path = os.path.join(
        args.output_dir, baseline_filename
    )
    html_path = os.path.join(
        args.output_dir, "security_dashboard.html"
    )
    markdown_path = os.path.join(
        args.output_dir, "executive_brief.md"
    )

    # Run the scan
    scanner = SecurityScanner(
        timeout=settings.get("default_timeout", 10),
        user_agent=settings.get(
            "user_agent",
            "SecurityAutomationToolkit/1.0",
        ),
        weights=weights,
    )
    scan_results = scanner.scan_endpoint(args.url)

    print(
        f"\n--- SCAN RESULTS: "
        f"{scan_results['target_url']} ---"
    )
    print(
        f"Score: {scan_results['security_score']} "
        f"({scan_results['grade']}) "
        f"- {scan_results['risk_level']} RISK"
    )
    print(
        "Missing headers: "
        f"{scan_results['missing_headers']}"
    )
    print(
        "Cookie violations: "
        f"{scan_results['cookie_violations']}"
    )
    print(
        "Forms found: "
        f"{len(scan_results['discovered_forms'])}"
    )
    robots = scan_results.get("robots", {})
    if robots.get("disallow_paths"):
        print(
            "robots.txt Disallow paths: "
            f"{robots['disallow_paths']}"
        )
    disclosures = scan_results.get(
        "server_disclosures", []
    )
    if disclosures:
        print(f"Server disclosures: {disclosures}")

    current_report = _map_findings_to_vulnerabilities(
        scan_results
    )

    # Load the previous baseline if one exists
    previous_baseline: Optional[Dict[str, Any]] = None
    if os.path.exists(baseline_path):
        try:
            with open(
                baseline_path, "r", encoding="utf-8"
            ) as f:
                previous_baseline = json.load(f)
            logger.info(
                "Loaded previous baseline: "
                f"{baseline_filename}"
            )
        except Exception as e:
            logger.error(
                f"Could not read baseline file: {e}"
            )
    else:
        logger.info(
            "No previous baseline found "
            "- this run becomes the baseline."
        )

    # Generate reports
    reporter = ComplianceReporter(
        findings=current_report,
        baseline=previous_baseline,
    )

    logger.info("Generating HTML report...")
    reporter.generate_html(output_path=html_path)

    logger.info("Generating Markdown summary...")
    md_content = reporter.generate_markdown_summary()
    try:
        with open(
            markdown_path, "w", encoding="utf-8"
        ) as f:
            f.write(md_content)
        logger.info(
            f"Markdown report saved: {markdown_path}"
        )
    except IOError as e:
        logger.error(
            f"Could not write Markdown report: {e}"
        )

    # Save current results as the new baseline
    try:
        with open(
            baseline_path, "w", encoding="utf-8"
        ) as f:
            json.dump(current_report, f, indent=4)
        logger.info(f"Baseline updated: {baseline_path}")
    except IOError as e:
        logger.error(f"Could not save baseline: {e}")


if __name__ == "__main__":
    main()
