import json
import logging
import os

logger = logging.getLogger("SecurityToolkit.Reporter")

class ComplianceReporter:
    def __init__(self, findings: dict):
        """Consumes the programmatic scan dictionary from security_score.py"""
        self.findings = findings

    def calculate_metrics(self) -> dict:
        """Calculates an objective risk metrics score mapped to the OWASP Top 10."""
        score = 100
        
        # Deduction rules based on security severity
        if not self.findings.get("tls_secured", False):
            score -= 30  # Massive impact on OWASP A04 (Cryptographic Failures)
        
        # Deduct 10 points per missing defensive header (OWASP A02)
        score -= (len(self.findings.get("missing_headers", [])) * 10) 
        
        # Deduct 10 points per unsecured cookie (OWASP A04)
        score -= (len(self.findings.get("cookie_violations", [])) * 10) 
        
        final_score = max(0, score)
        
        return {
            "score": final_score,
            "grade": "A" if final_score >= 90 else "B" if final_score >= 80 else "C" if final_score >= 70 else "F"
        }

    def write_json_report(self, filepath="security_report.json"):
        """Dumps standardized risk telemetry definitions into a clean file artifact."""
        metrics = self.calculate_metrics()
        
        report_payload = {
            "audit_target": self.findings.get("target_url"),
            "compliance_summary": {
                "owasp_alignment_score": metrics["score"],
                "grade_evaluation": metrics["grade"],
                "status": "PASS" if metrics["score"] >= 70 else "FAIL_NEEDS_REMEDIATION"
            },
            "raw_vulnerability_telemetry": self.findings
        }
        
        try:
            with open(filepath, "w") as f:
                json.dump(report_payload, f, indent=4)
            logger.info(f"Production compliance profile successfully exported to {filepath}")
            return True
        except IOError as e:
            logger.error(f"Failed to generate structured report artifact: {str(e)}")
            return False
