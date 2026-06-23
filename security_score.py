"""
Security Automation Toolkit - CLI Scanner Execution Engine with Dynamic Scoring.

This module orchestrates deterministic, OWASP-aligned security posture evaluations
against website targets, incorporating a dynamic risk deduction weight matrix.
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
        
        :param findings: The raw telemetry findings dictionary.
        :return: An updated dictionary appended with posture evaluation scores.
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

        # Run findings through the dynamic scoring logic step before returning
        return self.calculate_risk_posture(findings)


def main():
    """
    Entry point for execution loops. Manages string parameters parsed from terminal invocation environments.
    """
    parser = argparse.ArgumentParser(description="Automated Website Security Audit Engine")
    parser.add_argument("--url", required=True, help="Target URL to assess")
    parser.add_argument("--output", required=False, default=None, help="Optional file path destination to output findings")
    args = parser.parse_args()

    scanner = SecurityScanner()
    scan_results = scanner.scan_endpoint(args.url)
    
    # Print the execution outputs including the new calculated metrics
    print(f"--- SCAN EXECUTION SUMMARY FOR {scan_results['target_url']} ---")
    print(f"Calculated Score: {scan_results['security_score']} ({scan_results['grade']}) - {scan_results['risk_level']} RISK")
    print(f"Missing Headers: {scan_results['missing_headers']}")
    print(f"Cookie Flags Violations: {scan_results['cookie_violations']}")
    print(f"Forms Discovered: {len(scan_results['discovered_forms'])}")

    if args.output is not None:
        try:
            output_dir = os.path.dirname(args.output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(args.output, "w", encoding="utf-8") as file:
                json.dump(scan_results, file, indent=4)
            logger.info(f"Vulnerability log metrics written successfully to target path: {args.output}")
        except IOError as e:
            logger.error(f"Failed to compile and write output report to {args.output}: {str(e)}")


if __name__ == "__main__":
    main()
