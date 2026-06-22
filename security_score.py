import sys
import argparse
import logging
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Initialize production-grade logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("SecurityToolkit.Engine")

class SecurityScanner:
    def __init__(self, timeout=10, user_agent="SecurityAutomationToolkit/1.0"):
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def scan_endpoint(self, url: str) -> dict:
        """Orchestrates security posture evaluation on a single real estate URL."""
        logger.info(f"Initiating security scanning profile for: {url}")
        
        findings = {
            "target_url": url,
            "tls_secured": False,
            "missing_headers": [],
            "cookie_violations": [],
            "discovered_forms": [],
            "errors": []
        }

        # Validate SSL/TLS enforcement (OWASP A04)
        parsed = urlparse(url)
        if parsed.scheme == "https":
            findings["tls_secured"] = True

        try:
            # Enforce request strict timeout limits to prevent pipeline hanging
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            # Evaluate Security Headers (OWASP A02)
            required_headers = [
                "Strict-Transport-Security", 
                "Content-Security-Policy", 
                "X-Frame-Options", 
                "X-Content-Type-Options"
            ]
            for header in required_headers:
                if header not in response.headers:
                    findings["missing_headers"].append(header)

            # Analyze Cookie Flag Configurations (OWASP A04)
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing 'Secure' directive")
                # Structural fallback check for HttpOnly attributes
                if not cookie.has_nonstandard_attr('HttpOnly') and 'httponly' not in [k.lower() for k in cookie._attributes]:
                    issues.append("Missing 'HttpOnly' directive")
                
                if issues:
                    findings["cookie_violations"].append({
                        "cookie_name": cookie.name,
                        "issues": issues
                    })

            # Form & Attack Surface Parsing (Targeting OWASP A03/A05 Injection/Config vectors)
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
        except requests.exceptions.RequestException as e:
            logger.error(f"Network transport level anomaly on {url}: {str(e)}")
            findings["errors"].append(f"Connection failure: {type(e).__name__}")

        return findings

def main():
    parser = argparse.ArgumentParser(description="Automated Website Security Audit Engine")
    parser.add_argument("--url", required=True, help="Target URL to assess")
    # Add the optional output path argument to resolve the unrecognized argument crash
    parser.add_argument("--output", required=False, help="Optional file path destination to output findings")
    args = parser.parse_args()

    scanner = SecurityScanner()
    scan_results = scanner.scan_endpoint(args.url)
    
    # Standard terminal log summary output
    print(f"\n--- SCAN EXECUTION SUMMARY FOR {scan_results['target_url']} ---")
    print(f"TLS Secured: {scan_results['tls_secured']}")
    print(f"Missing Headers: {scan_results['missing_headers']}")
    print(f"Cookie Flags Violations: {scan_results['cookie_violations']}")
    print(f"Forms Discovered: {len(scan_results['discovered_forms'])}")
    if scan_results['errors']:
        print(f"Pipeline Errors: {scan_results['errors']}")

    # If the user supplied an --output path flag, write metrics data directly to it
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as file:
                # Serializes findings cleanly to a file (interim step prior to Phase 3 Dashboard HTML engine)
                json.dump(scan_results, file, indent=4)
            logger.info(f"Vulnerability log metrics written successfully to target path: {args.output}")
        except IOError as e:
            logger.error(f"Failed to compile and write output report to {args.output}: {str(e)}")

if __name__ == "__main__":
    main()
```
