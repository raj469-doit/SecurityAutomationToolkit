"""
Security Automation Toolkit - Compliance Reporting Engine (Phase 3)
===================================================================

This module processes raw, deterministic vulnerability dictionaries yielded by
the core scanning suite (`security_score.py`), aggregates high-level compliance
metrics, maps results to OWASP Top 10 classifications, handles historical differential
analysis, and compiles standalone HTML dashboards and Markdown summaries.

Architecture Guidelines:
- Strict Decoupling: Zero direct network or disk interfaces inside primary logic.
- Pure Python Templating: Minimizes container footprint in execution runners.
- Thread-Safe Logging: Integrates with the central toolkit logger.
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional

# Initialize a module-level logger attached to the framework's namespace hierarchy
logger = logging.getLogger("SecurityToolkit.Reporter")


class ComplianceReporter:
    """
    Analyzes raw diagnostic vulnerability dictionaries and formats compliance assets.
    Supports historical baseline comparisons to track newly introduced or resolved exposures.
    """

    def __init__(self, findings: Dict[str, Any], baseline: Optional[Dict[str, Any]] = None) -> None:
        """
        Initializes the reporter engine with execution findings and an optional baseline.

        Args:
            findings (Dict[str, Any]): Current execution vulnerabilities and metadata.
            baseline (Dict[str, Any], optional): Prior execution findings for delta calculations.
        """
        self.findings: Dict[str, Any] = findings
        self.baseline: Optional[Dict[str, Any]] = baseline
        self.deltas: Dict[str, Any] = self._calculate_deltas()

    def _calculate_deltas(self) -> Dict[str, Any]:
        """
        Internal helper to evaluate fixed vs. new vulnerabilities using set operations
        on unique vulnerability descriptions.
        """
        if not self.baseline:
            return {"new": [], "fixed": [], "score_delta": 0}

        current_vulns = self.findings.get("vulnerabilities", [])
        past_vulns = self.baseline.get("vulnerabilities", [])

        current_map = {v.get("description"): v for v in current_vulns if v.get("description")}
        past_map = {v.get("description"): v for v in past_vulns if v.get("description")}

        new_keys = set(current_map.keys()) - set(past_map.keys())
        fixed_keys = set(past_map.keys()) - set(current_map.keys())

        score_delta = self.findings.get("final_score", 100) - self.baseline.get("final_score", 100)

        return {
            "new": [current_map[k] for k in new_keys],
            "fixed": [past_map[k] for k in fixed_keys],
            "score_delta": score_delta
        }

    def compile_metrics(self) -> Dict[str, Any]:
        """
        Extracts executive dashboard metrics and breakdown metadata from findings.
        """
        vulnerabilities = self.findings.get("vulnerabilities", [])
        
        metrics: Dict[str, Any] = {
            "total_vulnerabilities": len(vulnerabilities),
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "owasp_breakdown": {}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            metrics[severity] = metrics.get(severity, 0) + 1
            
            owasp_cat = vuln.get("owasp_category", "Uncategorized")
            metrics["owasp_breakdown"][owasp_cat] = metrics["owasp_breakdown"].get(owasp_cat, 0) + 1
            
        return metrics

    def generate_markdown_summary(self) -> str:
        """
        Compiles execution metrics and historical deltas into an executive Markdown brief
        suitable for ticketing systems, markdown viewers, or notification systems.
        """
        target = self.findings.get("target", "Unknown Target")
        score = self.findings.get("final_score", 100)
        metrics = self.compile_metrics()

        # Build basic header and score trends
        trend_str = ""
        if self.baseline:
            delta = self.deltas["score_delta"]
            trend_str = f" ({'+' if delta >= 0 else ''}{delta} vs baseline)"

        md = f"""# Executive Security Briefing: {target}
**Security Posture Score:** {score}/100{trend_str}

## Risk Distribution Dashboard
- **Total Active Issues:** {metrics['total_vulnerabilities']}
  - **High Severity:** {metrics['High']}
  - **Medium Severity:** {metrics['Medium']}
  - **Low Severity:** {metrics['Low']}

"""
        # Append Historical Tracking Info if present
        if self.baseline:
            md += "## Historical Scan Aggregation (Deltas)\n"
            if not self.deltas["new"] and not self.deltas["fixed"]:
                md += "- No structural configuration deviations detected compared to baseline.\n\n"
            else:
                if self.deltas["new"]:
                    md += "### 🛑 Newly Introduced Exposures\n"
                    for nv in self.deltas["new"]:
                        md += f"- **[{nv.get('severity')}]** {nv.get('owasp_category')} - *{nv.get('description')}*\n"
                if self.deltas["fixed"]:
                    md += "\n### 🎉 Resolved Vulnerabilities\n"
                    for fv in self.deltas["fixed"]:
                        md += f"- **[{fv.get('severity')}]** {fv.get('owasp_category')} - *{fv.get('description')}*\n"
            md += "\n"

        # Append Vulnerability Detail Lists
        md += "## Remediation Action Plan\n"
        vulns = self.findings.get("vulnerabilities", [])
        if vulns:
            for i, v in enumerate(vulns, start=1):
                md += f"{i}. **{v.get('owasp_category')}** [{v.get('severity')}]\n"
                md += f"   - **Description:** {v.get('description')}\n"
                md += f"   - **Remediation:** {v.get('remediation')}\n"
        else:
            md += "No outstanding vulnerabilities require immediate mediation.\n"

        return md

    def generate_html(self, output_path: str) -> None:
        """
        Compiles the interactive metrics dashboard, deltas, and vulnerabilities 
        into a flat HTML report file. Includes CSS-only visualization widgets.
        """
        metrics = self.compile_metrics()
        target = self.findings.get("target", "Unknown Target")
        score = self.findings.get("final_score", 100)
        
        # Calculate visualization bar dimensions
        total = metrics['total_vulnerabilities']
        high_pct = (metrics['High'] / total * 100) if total > 0 else 0
        med_pct = (metrics['Medium'] / total * 100) if total > 0 else 0
        low_pct = (metrics['Low'] / total * 100) if total > 0 else 0

        # Build out dynamic row injection
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

        # Build dynamic delta markup for HTML view if baseline exists
        delta_section = ""
        if self.baseline:
            delta_section = f"""
            <div class="delta-card">
                <h3>Historical Baseline Variance</h3>
                <p>Score Trend: <strong>{"+" if self.deltas["score_delta"] >= 0 else ""}{self.deltas["score_delta"]} points</strong></p>
                <p>New Exposures: <span class="text-danger">{len(self.deltas["new"])}</span> | Resolved Issues: <span class="text-success">{len(self.deltas["fixed"])}</span></p>
            </div>
            """

        score_color = '#10b981' if score >= 80 else '#f59e0b' if score >= 50 else '#ef4444'

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Scan Dashboard - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 30px; background-color: #f8fafc; color: #1e293b; }}
        .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); max-width: 1100px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #0f172a; margin-top: 0; }}
        .header-layout {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 25px; }}
        .score {{ font-size: 32px; font-weight: bold; color: {score_color}; }}
        
        /* Visualization Metric Progress Track */
        .chart-container {{ background: #e2e8f0; height: 24px; border-radius: 12px; display: flex; overflow: hidden; margin: 20px 0; }}
        .bar-high {{ background-color: #ef4444; width: {high_pct}%; }}
        .bar-med {{ background-color: #f59e0b; width: {med_pct}%; }}
        .bar-low {{ background-color: #3b82f6; width: {low_pct}%; }}
        
        .delta-card {{ background-color: #f1f5f9; padding: 15px; border-radius: 8px; border-left: 4px solid #64748b; margin-bottom: 25px; }}
        .text-danger {{ color: #ef4444; font-weight: bold; }}
        .text-success {{ color: #10b981; font-weight: bold; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background-color: #f8fafc; color: #64748b; font-weight: 600; }}
        .badge-high {{ color: white; background: #ef4444; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-medium {{ color: white; background: #f59e0b; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-low {{ color: white; background: #3b82f6; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header-layout">
            <div>
                <h1>Security Assessment Dashboard</h1>
                <p style="margin: 0; color: #64748b;"><strong>Target Domain:</strong> {target}</p>
            </div>
            <div class="score">{score}/100</div>
        </div>

        {delta_section}

        <h2>Distribution of Severity Risk</h2>
        <div class="chart-container">
            <div class="bar-high" title="High Risk"></div>
            <div class="bar-med" title="Medium Risk"></div>
            <div class="bar-low" title="Low Risk"></div>
        </div>

        <h2>Vulnerability Remediation Matrix</h2>
        <table>
            <thead>
                <tr>
                    <th>OWASP Classification</th>
                    <th>Severity</th>
                    <th>Vulnerability Description</th>
                    <th>Suggested Remediation</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows if vuln_rows else "<tr><td colspan='4' style='text-align: center; color: #10b981;'>No vulnerabilities found! Core configurations are structurally sound.</td></tr>"}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        try:
            parent_dir = os.path.dirname(output_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"Interactive visual report saved: {output_path}")
        except Exception as e:
            logger.error(f"Failed to compile and drop visual report to disk: {str(e)}")


def create_html_report(findings: Dict[str, Any], output_path: str = "report.html", baseline: Optional[Dict[str, Any]] = None) -> None:
    """Convenience functional wrapper matching legacy integration signatures."""
    reporter = ComplianceReporter(findings, baseline=baseline)
    reporter.generate_html(output_path)
