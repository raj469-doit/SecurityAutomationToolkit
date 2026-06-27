"""
Security Automation Toolkit - Report generator.

Takes the vulnerability findings from security_score.py and produces:
  - A standalone HTML dashboard
  - A Markdown executive summary

Can be imported as a module (ComplianceReporter) or run directly:
  python generate_report.py --input scan.json --output reports/
"""

import argparse
import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("SecurityToolkit.Reporter")


class ComplianceReporter:
    """
    Builds HTML and Markdown reports from a scan findings dict.
    Optionally compares against a previous scan to highlight new or fixed issues.
    """

    def __init__(
        self,
        findings: Dict[str, Any],
        baseline: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Args:
            findings: Current scan results from security_score.py.
            baseline: Previous scan results for comparison (optional).
        """
        self.findings: Dict[str, Any] = findings
        self.baseline: Optional[Dict[str, Any]] = baseline
        self.deltas: Dict[str, Any] = self._calculate_deltas()

    def _calculate_deltas(self) -> Dict[str, Any]:
        """
        Compare current findings against the baseline to find new and fixed issues.
        Returns a dict with 'new', 'fixed', and 'score_delta' keys.
        """
        if not self.baseline:
            return {"new": [], "fixed": [], "score_delta": 0}

        current_vulns = self.findings.get("vulnerabilities", [])
        past_vulns = self.baseline.get("vulnerabilities", [])

        current_map = {v["description"]: v for v in current_vulns if v.get("description")}
        past_map = {v["description"]: v for v in past_vulns if v.get("description")}

        new_keys = set(current_map) - set(past_map)
        fixed_keys = set(past_map) - set(current_map)

        score_delta = (
            self.findings.get("final_score", 100)
            - self.baseline.get("final_score", 100)
        )

        return {
            "new": [current_map[k] for k in new_keys],
            "fixed": [past_map[k] for k in fixed_keys],
            "score_delta": score_delta,
        }

    def compile_metrics(self) -> Dict[str, Any]:
        """Count vulnerabilities by severity and OWASP category."""
        vulnerabilities = self.findings.get("vulnerabilities", [])
        metrics: Dict[str, Any] = {
            "total_vulnerabilities": len(vulnerabilities),
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "owasp_breakdown": {},
        }
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            metrics[severity] = metrics.get(severity, 0) + 1
            cat = vuln.get("owasp_category", "Uncategorized")
            metrics["owasp_breakdown"][cat] = metrics["owasp_breakdown"].get(cat, 0) + 1
        return metrics

    def generate_markdown_summary(self) -> str:
        """Return a Markdown executive summary as a string."""
        target = self.findings.get("target", "Unknown")
        score = self.findings.get("final_score", 100)
        metrics = self.compile_metrics()

        trend = ""
        if self.baseline:
            delta = self.deltas["score_delta"]
            sign = "+" if delta >= 0 else ""
            trend = f" ({sign}{delta} vs previous scan)"

        md = f"""# Security Report: {target}

**Score:** {score}/100{trend}

## Summary

- **Total issues:** {metrics['total_vulnerabilities']}
- **High severity:** {metrics['High']}
- **Medium severity:** {metrics['Medium']}
- **Low severity:** {metrics['Low']}

"""

        if self.baseline:
            md += "## Changes Since Last Scan\n"
            if not self.deltas["new"] and not self.deltas["fixed"]:
                md += "No changes from the previous scan.\n\n"
            else:
                if self.deltas["new"]:
                    md += "### 🛑 New Issues\n"
                    for v in self.deltas["new"]:
                        md += f"- **[{v.get('severity')}]** {v.get('owasp_category')} — {v.get('description')}\n"
                if self.deltas["fixed"]:
                    md += "\n### ✅ Fixed Issues\n"
                    for v in self.deltas["fixed"]:
                        md += f"- **[{v.get('severity')}]** {v.get('owasp_category')} — {v.get('description')}\n"
                md += "\n"

        md += "## Findings and Remediation\n"
        vulns = self.findings.get("vulnerabilities", [])
        if vulns:
            for i, v in enumerate(vulns, start=1):
                md += f"{i}. **{v.get('owasp_category')}** [{v.get('severity')}]\n"
                md += f"   - **Issue:** {v.get('description')}\n"
                md += f"   - **Fix:** {v.get('remediation')}\n"
        else:
            md += "No issues found.\n"

        return md

    def generate_html(self, output_path: str) -> None:
        """Write a standalone HTML dashboard to output_path."""
        metrics = self.compile_metrics()
        target = self.findings.get("target", "Unknown")
        score = self.findings.get("final_score", 100)

        total = metrics["total_vulnerabilities"]
        high_pct = (metrics["High"] / total * 100) if total > 0 else 0
        med_pct = (metrics["Medium"] / total * 100) if total > 0 else 0
        low_pct = (metrics["Low"] / total * 100) if total > 0 else 0

        vuln_rows = ""
        for vuln in self.findings.get("vulnerabilities", []):
            vuln_rows += f"""
            <tr>
              <td><strong>{vuln.get('owasp_category')}</strong></td>
              <td><span class="badge-{vuln.get('severity', 'Low').lower()}">{vuln.get('severity')}</span></td>
              <td>{vuln.get('description')}</td>
              <td>{vuln.get('remediation')}</td>
            </tr>"""

        delta_section = ""
        if self.baseline:
            sign = "+" if self.deltas["score_delta"] >= 0 else ""
            delta_section = f"""
            <div class="delta-card">
              <h3>Changes Since Last Scan</h3>
              <p>Score change: <strong>{sign}{self.deltas['score_delta']} points</strong></p>
              <p>
                New issues: <span class="text-danger">{len(self.deltas['new'])}</span> &nbsp;|&nbsp;
                Fixed: <span class="text-success">{len(self.deltas['fixed'])}</span>
              </p>
            </div>"""

        score_color = (
            "#10b981" if score >= 80
            else "#f59e0b" if score >= 50
            else "#ef4444"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Report — {target}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      margin: 30px; background: #f8fafc; color: #1e293b;
    }}
    .container {{
      background: white; padding: 30px; border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05); max-width: 1100px; margin: 0 auto;
    }}
    h1, h2, h3 {{ color: #0f172a; margin-top: 0; }}
    .header-layout {{
      display: flex; justify-content: space-between; align-items: center;
      border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 25px;
    }}
    .score {{ font-size: 32px; font-weight: bold; color: {score_color}; }}
    .chart-container {{
      background: #e2e8f0; height: 24px; border-radius: 12px;
      display: flex; overflow: hidden; margin: 20px 0;
    }}
    .bar-high {{ background: #ef4444; width: {high_pct}%; }}
    .bar-med  {{ background: #f59e0b; width: {med_pct}%; }}
    .bar-low  {{ background: #3b82f6; width: {low_pct}%; }}
    .delta-card {{
      background: #f1f5f9; padding: 15px; border-radius: 8px;
      border-left: 4px solid #64748b; margin-bottom: 25px;
    }}
    .text-danger {{ color: #ef4444; font-weight: bold; }}
    .text-success {{ color: #10b981; font-weight: bold; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
    th {{ background: #f8fafc; color: #64748b; font-weight: 600; }}
    .badge-high   {{ color: white; background: #ef4444; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    .badge-medium {{ color: white; background: #f59e0b; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    .badge-low    {{ color: white; background: #3b82f6; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-layout">
      <div>
        <h1>Security Report</h1>
        <p style="margin:0; color:#64748b;"><strong>Target:</strong> {target}</p>
      </div>
      <div class="score">{score}/100</div>
    </div>

    {delta_section}

    <h2>Severity Breakdown</h2>
    <div class="chart-container">
      <div class="bar-high" title="High"></div>
      <div class="bar-med"  title="Medium"></div>
      <div class="bar-low"  title="Low"></div>
    </div>

    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>OWASP Category</th>
          <th>Severity</th>
          <th>Description</th>
          <th>Fix</th>
        </tr>
      </thead>
      <tbody>
        {vuln_rows if vuln_rows else
         "<tr><td colspan='4' style='text-align:center; color:#10b981;'>No issues found.</td></tr>"}
      </tbody>
    </table>
  </div>
</body>
</html>
"""

        try:
            parent = os.path.dirname(output_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report saved: {output_path}")
        except Exception as e:
            logger.error(f"Could not write HTML report: {str(e)}")


def create_html_report(
    findings: Dict[str, Any],
    output_path: str = "report.html",
    baseline: Optional[Dict[str, Any]] = None,
) -> None:
    """Convenience wrapper for callers that use the old functional API."""
    ComplianceReporter(findings, baseline=baseline).generate_html(output_path)


def main() -> None:
    """
    Run the reporter standalone.

    Usage:
        python generate_report.py --input scan.json --output reports/dashboard.html
    """
    parser = argparse.ArgumentParser(description="Generate a security report from a scan JSON file")
    parser.add_argument("--input", required=True, help="Path to scan JSON (output of security_score.py)")
    parser.add_argument("--output", required=True, help="Path for the HTML report file")
    parser.add_argument("--baseline", help="Path to a previous scan JSON for diff comparison (optional)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    with open(args.input, "r", encoding="utf-8") as f:
        findings = json.load(f)

    baseline = None
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, "r", encoding="utf-8") as f:
            baseline = json.load(f)

    reporter = ComplianceReporter(findings=findings, baseline=baseline)
    reporter.generate_html(output_path=args.output)

    md_path = args.output.replace(".html", ".md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(reporter.generate_markdown_summary())
    logger.info(f"Markdown summary saved: {md_path}")


if __name__ == "__main__":
    main()
