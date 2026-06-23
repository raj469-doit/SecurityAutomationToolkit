"""
Security Automation Toolkit - CLI Scanner Execution Engine with Dynamic Scoring.

This module orchestrates deterministic, OWASP-aligned security posture evaluations
against website targets, incorporating a dynamic risk deduction weight matrix.
Integrates with ComplianceReporter to auto-generate Phase 3 visual HTML and Markdown briefs.
"""

import os
import sys
import argparse
import logging
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Import the reporting components natively from your updated reporting module
from generate_report import ComplianceReporter

# Initialize production-grade logging format for structural pipeline monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("SecurityToolkit.Engine")


class SecurityScanner:
    """
    A robust web security scanner engine featuring header checks, transport 
    layer analysis, and an automated risk scoring calculation matrix.
    """

    def __init__(self, timeout=10, user_agent="SecurityAutomationToolkit/1.0"):
        """
        Initializes the scanner session attributes.
        """
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def calculate_risk_posture(self, findings: dict) -> dict:
        """
        Processes findings through a deductive risk matrix to calculate
        the baseline security score, grade, and classification level.
        """
        score = 100

        # 1. Deduct for non-TLS/HTTPS channel deployment (OWASP A04:2021)
        if not findings["tls_secured"]:
            score -= 25
            logger.warning("Deducting 25 points: Channel lacks secure TLS/HTTPS encapsulation.")

        # 2. Deduct for missing high-impact security headers (OWASP A05:2021)
        high_risk_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
        medium_risk_headers = ["X-Frame-Options", "X-Content-Type-Options"]

        for header in findings["missing_headers"]:
            if header in high_risk_headers:
                score -= 15
                logger.warning(f"Deducting 15 points: Missing high-risk header '{header}'.")
            elif header in medium_risk_headers:
                score -= 10
                logger.warning(f"Deducting 10 points: Missing medium-risk header '{header}'.")

        # 3. Deduct for high-priority cookie parameter failures
        for violation in findings["cookie_violations"]:
            for issue in violation["issues"]:
                if "Secure" in issue:
                    score -= 20
                    logger.warning(f"Deducting 20 points: Cookie '{violation['cookie_name']}' missing Secure flag.")
                elif "HttpOnly" in issue:
                    score -= 10
                    logger.warning(f"Deducting 10 points: Cookie '{violation['cookie_name']}' missing HttpOnly flag.")

        # Enforce mathematical boundaries between 0 and 100
        score = max(0, min(100, score))
        findings["security_score"] = score

        # 4. Map the numeric score to an enterprise-grade classification scale
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

        logger.info(f"Final calculated security metrics posture: Score={score}, Grade={findings['grade']}, Risk={findings['risk_level']}")
        return findings

    def scan_endpoint(self, url: str) -> dict:
        """
        Orchestrates security posture evaluation on a single URL target.
        """
        logger.info(f"Initiating security scanning profile for: {url}")
        
        findings = {
            "target_url": url,
            "tls_secured": False,
            "security_score": 100,
            "grade": "A",
            "risk_level": "LOW",
            "missing_headers": [],
            "cookie_violations": [],
            "discovered_forms": [],
            "errors": []
        }

        parsed = urlparse(url)
        if parsed.scheme == "https":
            findings["tls_secured"] = True

        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            required_headers = [
                "Strict-Transport-Security", 
                "Content-Security-Policy", 
                "X-Frame-Options", 
                "X-Content-Type-Options"
            ]
            for header in required_headers:
                if header not in response.headers:
                    findings["missing_headers"].append(header)

            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing 'Secure' directive")
                if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in [k.lower() for k in cookie._attributes]:
                    issues.append("Missing 'HttpOnly' directive")
                
                if issues:
                    findings["cookie_violations"].append({
                        "cookie_name": cookie.name,
                        "issues": issues
                    })

            soup = BeautifulSoup(response.text, 'html.parser')
            for index, form in enumerate(soup.find_all('form')):
                inputs = [inp.get('name') for inp in form.find_all(['input', 'textarea']) if inp.get('name')]
                findings["discovered_forms"].append({
                    "form_index": index,
                    "action": form.get('action', ''),
                    "method": form.get('method', 'get').lower(),
                    "input_parameters": inputs
                })

        except requests.exceptions.Timeout:
            logger.error(f"Scan timed out for destination: {url}")
            findings["errors"].append("Network timeout error occurred")
            findings["security_score"] = 0
            findings["grade"] = "F"
            findings["risk_level"] = "CRITICAL"
            return findings
        except requests.exceptions.RequestException as e:
            logger.error(f"Network transport level anomaly on {url}: {str(e)}")
            findings["errors"].append(f"Connection failure: {type(e).__name__}")
            findings["security_score"] = 0
            findings["grade"] = "F"
            findings["risk_level"] = "CRITICAL"
            return findings

        return self.calculate_risk_posture(findings)


def _map_telemetry_to_vulnerabilities(scan_results: dict) -> dict:
    """
    Transforms raw telemetry findings map into the normalized structural dictionary contract 
    expected natively by the ComplianceReporter engine core.
    """
    vulnerabilities = []

    if not scan_results["tls_secured"]:
        vulnerabilities.append({
            "owasp_category": "A04:2021-Cryptographic Failures",
            "severity": "High",
            "description": f"Unencrypted communication channel deployed over plaintext protocol scheme.",
            "remediation": "Enforce sitewide permanent HSTS redirection protocols and bind application to TLS 1.3 endpoints."
        })

    high_risk_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
    for header in scan_results["missing_headers"]:
        severity = "High" if header in high_risk_headers else "Medium"
        vulnerabilities.append({
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": severity,
            "description": f"Missing HTTP security architecture directive header configuration: '{header}'.",
            "remediation": f"Configure backend routing engine server blocks to inject explicit parameter declarations for '{header}'."
        })

    for cv in scan_results["cookie_violations"]:
        for issue in cv["issues"]:
            severity = "High" if "Secure" in issue else "Medium"
            vulnerabilities.append({
                "owasp_category": "A05:2021-Security Misconfiguration",
                "severity": severity,
                "description": f"Session identity token element cookie '{cv['cookie_name']}' dropped with '{issue}'.",
                "remediation": f"Audit middleware interceptor logic state to bind appropriate security directives natively onto application runtime contexts."
            })

    return {
        "target": scan_results["target_url"],
        "final_score": scan_results["security_score"],
        "vulnerabilities": vulnerabilities
    }


def _get_domain_filename(url: str) -> str:
    """
    Extracts and sanitizes the hostname from a URL to create a unique,
    domain-scoped filename for tracking historical baselines.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path
        # Sanitize string: remove common prefixes and replace dots/special chars with underscores
        clean_name = hostname.replace("www.", "").replace(".", "_").replace(":", "_")
        return f"latest_scan_{clean_name}.json"
    except Exception:
        return "latest_scan_fallback.json"


def main():
    """
    Entry point for execution loops. Controls execution metrics collection, 
    historical baseline differential processing, and Phase 3 asset dumps.
    """
    parser = argparse.ArgumentParser(description="Automated Website Security Audit Engine")
    parser.add_argument("--url", required=True, help="Target URL to assess")
    parser.add_argument("--output-dir", required=False, default="outputs", help="Directory target location for reporting asset generation")
    args = parser.parse_args()

    # Create target pipeline directories up front
    os.makedirs(args.output_dir, exist_ok=True)
    
    # NEW: Dynamically resolve the tracking file based strictly on the target domain
    domain_scoped_filename = _get_domain_filename(args.url)
    raw_json_baseline_path = os.path.join(args.output_dir, domain_scoped_filename)
    
    # Generic user-facing dashboard paths (overwritten per run for easy viewing)
    html_dashboard_path = os.path.join(args.output_dir, "security_dashboard.html")
    markdown_brief_path = os.path.join(args.output_dir, "executive_brief.md")

    # Run the core scanning operations loop
    scanner = SecurityScanner()
    scan_results = scanner.scan_endpoint(args.url)
    
    print(f"\n--- SCAN EXECUTION SUMMARY FOR {scan_results['target_url']} ---")
    print(f"Calculated Score: {scan_results['security_score']} ({scan_results['grade']}) - {scan_results['risk_level']} RISK")
    print(f"Missing Headers: {scan_results['missing_headers']}")
    print(f"Cookie Flags Violations: {scan_results['cookie_violations']}")
    print(f"Forms Discovered: {len(scan_results['discovered_forms'])}")

    # 1. Structural schema adaptation translation step
    current_report_payload = _map_telemetry_to_vulnerabilities(scan_results)

    # 2. Extract historical tracking metrics state cache if verified
    historical_baseline_payload = None
    if os.path.exists(raw_json_baseline_path):
        try:
            with open(raw_json_baseline_path, "r", encoding="utf-8") as f:
                historical_baseline_payload = json.load(f)
            logger.info(f"Historical baseline found for this specific domain ({domain_scoped_filename}). Evaluating deltas...")
        except Exception as e:
            logger.error(f"Historical state mapping ingestion failure anomaly: {str(e)}")
    else:
        logger.info(f"No previous baseline found for this specific domain. Treating as a baseline anchor scan.")

    # 3. Instantiate reporting pipeline engine core interface
    reporter = ComplianceReporter(findings=current_report_payload, baseline=historical_baseline_payload)

    # 4. Generate Interactive Visualization Dashboard Block
    logger.info("Compiling dynamic standalone HTML5 visualization assets...")
    reporter.generate_html(output_path=html_dashboard_path)

    # 5. Generate Standalone Executive Brief Markdown Summaries
    logger.info("Compiling high-level Markdown executive documentation brief...")
    markdown_document_string = reporter.generate_markdown_summary()
    try:
        with open(markdown_brief_path, "w", encoding="utf-8") as f:
            f.write(markdown_document_string)
        logger.info(f"Executive Markdown brief successfully saved to pathway: {markdown_brief_path}")
    except IOError as e:
        logger.error(f"Failed to commit Markdown compliance brief out to disk stream interface: {str(e)}")

    # 6. Cycle state signatures so current runs become next execution baseline anchors
    try:
        with open(raw_json_baseline_path, "w", encoding="utf-8") as f:
            json.dump(current_report_payload, f, indent=4)
        logger.info(f"Scan signatures updated successfully. Saved historical state tracking reference anchor: {raw_json_baseline_path}")
    except IOError as e:
        logger.error(f"Failed to cache persistent scanning transaction telemetry onto disk boundaries: {str(e)}")


if __name__ == "__main__":
    main()
