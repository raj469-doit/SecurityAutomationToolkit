"""
Security Automation Toolkit - CLI Scanner Execution Engine.

This module orchestrates deterministic, OWASP-aligned security posture evaluations
against website targets. It unifies troubleshooting, QA validation, and cybersecurity
best practices to identify infrastructure and application-level vulnerabilities.
"""

import os
import sys
import argparse
import logging
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Initialize production-grade logging format for structural pipeline monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("SecurityToolkit.Engine")

# =====================================================================
# ADD THIS TO THE TOP PORTION OR CLASS DEFINITIONS IN security_score.py
# =====================================================================

class SecurityScorer:
    """
    Evaluates scan postures using a Weighted Severity and Deductive Scoring Model,
    mapped conceptually to industry standard severity tiers (CVSS/OWASP).
    """
    def __init__(self):
        self.SEVERITY_WEIGHTS = {
            "CRITICAL": 50,
            "HIGH": 30,
            "MEDIUM": 15,
            "LOW": 5
        }
        
    def calculate_score(self, scan_results: dict) -> dict:
        base_score = 100
        total_deductions = 0
        detailed_deductions = []

        # 1. SSL/TLS Status Check
        if not scan_results.get("ssl_valid", True):
            deduction = self.SEVERITY_WEIGHTS["CRITICAL"]
            total_deductions += deduction
            detailed_deductions.append(f"CRITICAL: Invalid or expired SSL Certificate (-{deduction} pts)")

        # 2. Security Headers Deductions Matrix
        missing_headers = scan_results.get("missing_headers", [])
        for header in missing_headers:
            if header in ["Content-Security-Policy", "X-Frame-Options"]:
                deduction = self.SEVERITY_WEIGHTS["HIGH"]
                total_deductions += deduction
                detailed_deductions.append(f"HIGH: Missing {header} header (-{deduction} pts)")
            elif header in ["Strict-Transport-Security"]:
                deduction = self.SEVERITY_WEIGHTS["MEDIUM"]
                total_deductions += deduction
                detailed_deductions.append(f"MEDIUM: Missing {header} header (-{deduction} pts)")
            else:
                deduction = self.SEVERITY_WEIGHTS["LOW"]
                total_deductions += deduction
                detailed_deductions.append(f"LOW: Missing {header} header (-{deduction} pts)")

        # 3. Session / Cookie Vulnerabilities 
        insecure_cookies = scan_results.get("insecure_cookies", 0)
        if insecure_cookies > 0:
            deduction = min(insecure_cookies * self.SEVERITY_WEIGHTS["MEDIUM"], 45) # Max penalty boundary cap
            total_deductions += deduction
            detailed_deductions.append(f"MEDIUM: {insecure_cookies} cookie(s) lacking Secure/HttpOnly flags (-{deduction} pts)")

        # Finalize Math Bounds
        final_score = max(0, base_score - total_deductions)
        
        # Risk Grade Categorization
        if final_score >= 90:
            grade = "A (Low Risk)"
        elif final_score >= 75:
            grade = "B (Medium Risk)"
        elif final_score >= 50:
            grade = "C (High Risk)"
        else:
            grade = "F (Critical Risk)"

        return {
            "score": final_score,
            "grade": grade,
            "breakdown": detailed_deductions
        }

# =====================================================================
# UPDATE YOUR CORE EXECUTION OR RUN LOOP IN security_score.py
# =====================================================================
# inside your execution coordinator function (e.g., main or scan runner):
#
# scan_payload = {
#     "ssl_valid": ssl_status,
#     "missing_headers": list_of_missing_headers,
#     "insecure_cookies": count_of_unsafe_cookies
# }
# scorer = SecurityScorer()
# final_metrics = scorer.calculate_score(scan_payload)
# logger.info(f"Scan Completed. Target Score: {final_metrics['score']} - Grade: {final_metrics['grade']}")

class SecurityScanner:
    """
    A robust web security scanner engine utilizing strict transport layer checks,
    response header parsing, and target discovery routines.
    """

    def __init__(self, timeout=10, user_agent="SecurityAutomationToolkit/1.0"):
        """
        Initializes the scanner session attributes.
        
        :param timeout: Maximum network transport wait-time in seconds before failing.
        :param user_agent: Ident string broadcast to target properties during mapping.
        """
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def scan_endpoint(self, url: str) -> dict:
        """
        Orchestrates security posture evaluation on a single URL target.
        
        Evaluates structural transport security, security header misconfigurations,
        cookie flag directives, and processes target dynamic attack surfaces.
        
        :param url: The absolute target URL destination to evaluate.
        :return: A dictionary payload encapsulating security telemetry and findings.
        """
        logger.info(f"Initiating security scanning profile for: {url}")
        
        # Core data structure containing findings mapped to respective vulnerability layers
        findings = {
            "target_url": url,
            "tls_secured": False,
            "missing_headers": [],
            "cookie_violations": [],
            "discovered_forms": [],
            "errors": []
        }

        # Validate SSL/TLS enforcement posture (Targeting OWASP A04:2021-Cryptographic Failures)
        parsed = urlparse(url)
        if parsed.scheme == "https":
            findings["tls_secured"] = True

        try:
            # Execute transport connection. Redirects are allowed to follow structural domain rules,
            # but standard strict timeout limits are enforced to prevent automated pipeline hanging.
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            # Evaluate Security Headers (Targeting OWASP A05:2021-Security Misconfiguration)
            # These directives establish host-level protections against XSS, clickjacking, and mime-sniffing.
            required_headers = [
                "Strict-Transport-Security", 
                "Content-Security-Policy", 
                "X-Frame-Options", 
                "X-Content-Type-Options"
            ]
            for header in required_headers:
                if header not in response.headers:
                    findings["missing_headers"].append(header)

            # Analyze Client Cookie Flag Configurations (Targeting OWASP A04:2021-Cryptographic Failures)
            # Validates that sensitive transaction handling vectors enforce state protection tokens.
            for cookie in response.cookies:
                issues = []
                # Ensure the cookie cannot be transmitted over unencrypted HTTP channels
                if not cookie.secure:
                    issues.append("Missing 'Secure' directive")
                
                # Structural fallback check for HttpOnly attributes to mitigate token theft via XSS injection
                if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in [k.lower() for k in cookie._attributes]:
                    issues.append("Missing 'HttpOnly' directive")
                
                if issues:
                    findings["cookie_violations"].append({
                        "cookie_name": cookie.name,
                        "issues": issues
                    })

            # Application Attack Surface Discovery (Targeting OWASP A03:2021-Injection vector mapping)
            # Beautiful Soup dynamically parses the DOM tree to track form ingestion targets.
            soup = BeautifulSoup(response.text, 'html.parser')
            for index, form in enumerate(soup.find_all('form')):
                # Gather names of input variables and text areas that represent potential attack strings
                inputs = [inp.get('name') for inp in form.find_all(['input', 'textarea']) if inp.get('name')]
                findings["discovered_forms"].append({
                    "form_index": index,
                    "action": form.get('action', ''),
                    "method": form.get('method', 'get').lower(),
                    "input_parameters": inputs
                })

        except requests.exceptions.Timeout:
            # Traps pipeline execution stalls safely for offline infrastructure targets
            logger.error(f"Scan timed out for destination: {url}")
            findings["errors"].append("Network timeout error occurred")
        except requests.exceptions.RequestException as e:
            # Traps down-level socket level anomalies, DNS resolution issues, or transport faults gracefully
            logger.error(f"Network transport level anomaly on {url}: {str(e)}")
            findings["errors"].append(f"Connection failure: {type(e).__name__}")

        return findings


def main():
    """
    Entry point for execution loops. Manages string parameters parsed from terminal invocation environments.
    """
    parser = argparse.ArgumentParser(description="Automated Website Security Audit Engine")
    
    # Define mandatory pipeline URL target string parameters
    parser.add_argument("--url", required=True, help="Target URL to assess")
    
    # Define optional output reporting paths; defaults to None to retain native compatibility with unit tests
    parser.add_argument("--output", required=False, default=None, help="Optional file path destination to output findings")
    args = parser.parse_args()

    # Initialize execution profile and generate metrics payload
    scanner = SecurityScanner()
    scan_results = scanner.scan_endpoint(args.url)
    
    # Log original output structural signatures directly back to console stdout for test capture frameworking
    print(f"--- SCAN EXECUTION SUMMARY FOR {scan_results['target_url']} ---")
    print(f"Missing Headers: {scan_results['missing_headers']}")
    print(f"Cookie Flags Violations: {scan_results['cookie_violations']}")
    print(f"Forms Discovered: {len(scan_results['discovered_forms'])}")

    # Conditional telemetry preservation logic layer (Isoles I/O executions cleanly away from QA test iterations)
    if args.output is not None:
        try:
            # Workspace Hardening Stage: Extract directory configurations and establish paths cleanly if missing
            output_dir = os.path.dirname(args.output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            # Safely compile the raw telemetry dictionary to disk as beautifully indented structured JSON data
            with open(args.output, "w", encoding="utf-8") as file:
                json.dump(scan_results, file, indent=4)
            logger.info(f"Vulnerability log metrics written successfully to target path: {args.output}")
        except IOError as e:
            logger.error(f"Failed to compile and write output report to {args.output}: {str(e)}")


if __name__ == "__main__":
    main()
