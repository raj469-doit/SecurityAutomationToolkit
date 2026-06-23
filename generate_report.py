"""
Security Automation Toolkit - Compliance Reporting Engine (Phase 3)
===================================================================

This module processes raw, deterministic vulnerability dictionaries yielded by
the core scanning suite (`security_score.py`), aggregates high-level compliance
metrics, maps results to OWASP Top 10 classifications, and compiles standalone,
zero-dependency HTML reports.

Architecture Guidelines:
- Strict Decoupling: Zero direct network or disk interfaces inside primary logic.
- Pure Python Templating: Minimizes container footprint in execution runners (e.g., GitHub Actions).
- Thread-Safe Logging: Integrates with the central toolkit logger.
"""

import json
import logging
import os
from typing import Dict, Any

# Initialize a module-level logger attached to the framework's namespace hierarchy
logger = logging.getLogger("SecurityToolkit.Reporter")


class ComplianceReporter:
    """
    Analyzes raw diagnostic vulnerability dictionaries and formats compliance assets.

    This class serves as the core transformation engine, converting structural 
    JSON/dictionary findings maps into aggregate metrics dashboards and downstream 
    presentation layers.
    """

    def __init__(self, findings: Dict[str, Any]) -> None:
        """
        Initializes the reporter engine with execution findings.

        Args:
            findings (Dict[str, Any]): A dictionary mapping containing raw execution details.
                Expected schema:
                {
                    "target": str,
                    "final_score": int,
                    "vulnerabilities": list[dict]
                }
        """
        self.findings: Dict[str, Any] = findings

    def compile_metrics(self) -> Dict[str, Any]:
        """
        Extracts executive dashboard metrics and breakdown metadata from findings.

        Iterates natively over data payloads to group findings by mathematical 
        severities and categorical OWASP Top 10 mappings without mutating state.

        Returns:
            Dict[str, Any]: A calculated matrix tracking critical metrics counters.
                Example:
                {
                    "total_vulnerabilities": 2,
                    "High": 1,
                    "Medium": 1,
                    "Low": 0,
                    "owasp_breakdown": {"A05:2021-Security Misconfiguration": 2}
                }
        """
        vulnerabilities = self.findings.get("vulnerabilities", [])
        
        # Initialize isolated summary tracking buffers
        metrics: Dict[str, Any] = {
            "total_vulnerabilities": len(vulnerabilities),
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "owasp_breakdown": {}
        }
        
        for vuln in vulnerabilities:
            # Safely fetch severity classifications with an optimistic default fall-through
            severity = vuln.get("severity", "Low")
            metrics[severity] = metrics.get(severity, 0) + 1
            
            # Map issues systematically against the designated OWASP taxonomies
            owasp_cat = vuln.get("owasp_category", "Uncategorized")
            metrics["owasp_breakdown"][owasp_cat] = metrics["owasp_breakdown"].get(owasp_cat, 0) + 1
            
        return metrics

    def generate_html(self, output_path: str) -> None:
        """
        Compiles the metrics dashboard and vulnerabilities into a flat HTML report file.

        Injects structural fields and metrics directly via strict string formatting 
        literals to remain lightweight and independent of external heavy 
        rendering frameworks like Jinja2.

        Args:
            output_path (str): The target file destination pathway on the disk interface.

        Raises:
            IOError: If writing to the defined output file path encounters OS constraints.
        """
        metrics = self.compile_metrics()
        target = self.findings.get("target", "Unknown Target")
        score = self.findings.get("final_score", 100)
        
        # Dynamically loop and build sanitized table rows for vulnerability line-items
        vuln_rows = ""
        for vuln in self.findings.get("vulnerabilities", []):
            vuln_rows += f"""
            <tr>
                <td><strong>{vuln.get('owasp_category')}</strong></td>
                <td><span class="badge-{vuln.get('severity', 'Low').lower()}">{vuln.get('severity')}</span></td>
                <td>{vuln.get('description')}</td>
                <td>{vuln.get('remediation')}</td>
            </tr>
            """

        # Choose the dynamic badge color representation depending on the clamping constraints
        score_color = '#10b981' if score >= 80 else '#f59e0b' if score >= 50 else '#ef4444'

        # Native standalone document configuration string template literal
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; color: #333; }}
        .container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #1e293b; }}
        .score {{ font-size: 24px; font-weight: bold; color: {score_color}; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background-color: #f8fafc; }}
        .badge-high {{ color: white; background: #ef4444; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .badge-medium {{ color: white; background: #f59e0b; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
        .badge-low {{ color: white; background: #3b82f6; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Summary</h1>
        <p><strong>Target URL:</strong> {target}</p>
        <p><strong>Security Posture Score:</strong> <span class="score">{score}/100</span></p>
        
        <h2>Dashboard Metrics</h2>
        <ul>
            <li>Total Issues Identified: {metrics['total_vulnerabilities']}</li>
            <li>High Severity: {metrics['High']}</li>
            <li>Medium Severity: {metrics['Medium']}</li>
            <li>Low Severity: {metrics['Low']}</li>
        </ul>

        <h2>Vulnerability Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>OWASP Category</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Remediation Step</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else "<tr><td colspan='4'>No vulnerabilities found! Clean scan.</td></tr>"}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        # Execute guarded filesystem modifications with comprehensive exception handlers
        try:
            # Ensure target parent directories exist before initialization
            parent_dir = os.path.dirname(output_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"Report successfully saved to target pathway: {output_path}")
        except Exception as e:
            logger.error(f"Failed to write HTML compliance report out to disk: {str(e)}")


def create_html_report(findings: Dict[str, Any], output_path: str = "report.html") -> None:
    """
    Exposed public utility interface function to invoke reporting routines.

    Simplifies interaction wrappers for upstream runner loops (e.g., inside 
    `security_score.py`), allowing a clean execution point right before script termination.

    Args:
        findings (Dict[str, Any]): The structured diagnostic results catalog tracking metrics.
        output_path (str, optional): Target output directory filename. Defaults to "report.html".
    """
    reporter = ComplianceReporter(findings)
    reporter.generate_html(output_path)
