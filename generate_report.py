"""
Security Automation Toolkit - Report generator.

Takes the vulnerability findings from security_score.py and produces:
  - A standalone HTML dashboard with severity charts and remediation checklist
  - A Markdown executive summary with prioritized findings

Can be imported as a module (ComplianceReporter) or run directly:
  python generate_report.py --input scan.json --output reports/
"""

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("SecurityToolkit.Reporter")

# Severity ordering for priority-sorted output
SEVERITY_ORDER: Dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
}


def _grade_label(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def _grade_color(grade: str) -> str:
    """Return a CSS color for a letter grade."""
    return {
        "A": "#10b981",
        "B": "#22c55e",
        "C": "#f59e0b",
        "D": "#f97316",
        "F": "#ef4444",
    }.get(grade, "#64748b")


class ComplianceReporter:
    """
    Builds HTML and Markdown reports from a scan findings dict.
    Optionally compares against a previous scan to highlight changes.
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
        Compare current findings against the baseline to find new
        and fixed issues. Returns a dict with 'new', 'fixed', and
        'score_delta' keys.
        """
        if not self.baseline:
            return {"new": [], "fixed": [], "score_delta": 0}

        current_vulns = self.findings.get("vulnerabilities", [])
        past_vulns = self.baseline.get("vulnerabilities", [])

        current_map = {
            v["description"]: v
            for v in current_vulns if v.get("description")
        }
        past_map = {
            v["description"]: v
            for v in past_vulns if v.get("description")
        }

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
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "owasp_breakdown": {},
        }
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Low")
            metrics[severity] = metrics.get(severity, 0) + 1
            cat = vuln.get("owasp_category", "Uncategorized")
            metrics["owasp_breakdown"][cat] = (
                metrics["owasp_breakdown"].get(cat, 0) + 1
            )
        return metrics

    def _sort_vulns_by_severity(
        self, vulns: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Sort vulnerabilities by severity (Critical first)."""
        return sorted(
            vulns,
            key=lambda v: SEVERITY_ORDER.get(
                v.get("severity", "Low"), 99
            ),
        )

    def generate_markdown_summary(self) -> str:
        """Return a Markdown executive summary as a string."""
        target = self.findings.get("target", "Unknown")
        score = self.findings.get("final_score", 100)
        grade = _grade_label(score)
        metrics = self.compile_metrics()
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )

        trend = ""
        if self.baseline:
            delta = self.deltas["score_delta"]
            sign = "+" if delta >= 0 else ""
            trend = f" ({sign}{delta} vs previous scan)"

        md = f"""# Security Assessment: {target}

**Generated:** {timestamp}
**Score:** {score}/100 (Grade: {grade}){trend}

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total issues | {metrics['total_vulnerabilities']} |
| Critical | {metrics['Critical']} |
| High | {metrics['High']} |
| Medium | {metrics['Medium']} |
| Low | {metrics['Low']} |

"""

        if self.baseline:
            md += "## Changes Since Last Scan\n\n"
            delta = self.deltas["score_delta"]
            sign = "+" if delta >= 0 else ""
            md += f"**Score change:** {sign}{delta} points\n\n"

            if not self.deltas["new"] and not self.deltas["fixed"]:
                md += "No changes from the previous scan.\n\n"
            else:
                if self.deltas["fixed"]:
                    md += "### \u2705 Fixed Issues\n\n"
                    for v in self._sort_vulns_by_severity(
                        self.deltas["fixed"]
                    ):
                        md += (
                            f"- **[{v.get('severity')}]** "
                            f"{v.get('owasp_category')} "
                            f"\u2014 {v.get('description')}\n"
                        )
                    md += "\n"
                if self.deltas["new"]:
                    md += "### \u26a0\ufe0f New Issues\n\n"
                    for v in self._sort_vulns_by_severity(
                        self.deltas["new"]
                    ):
                        md += (
                            f"- **[{v.get('severity')}]** "
                            f"{v.get('owasp_category')} "
                            f"\u2014 {v.get('description')}\n"
                        )
                    md += "\n"

        md += "## Remediation Checklist\n\n"
        md += (
            "Prioritized by severity. Address Critical "
            "and High items before deployment.\n\n"
        )
        vulns = self._sort_vulns_by_severity(
            self.findings.get("vulnerabilities", [])
        )
        if vulns:
            for i, v in enumerate(vulns, start=1):
                sev = v.get("severity", "Low")
                icon = {
                    "Critical": "\U0001f534",
                    "High": "\U0001f7e0",
                    "Medium": "\U0001f7e1",
                    "Low": "\U0001f7e2",
                }.get(sev, "\u26aa")
                md += (
                    f"{i}. {icon} **[{sev}]** "
                    f"{v.get('owasp_category')}\n"
                )
                md += (
                    f"   - **Issue:** "
                    f"{v.get('description')}\n"
                )
                md += (
                    f"   - **Fix:** "
                    f"{v.get('remediation')}\n"
                )
                md += "\n"
        else:
            md += "\u2705 No issues found.\n"

        md += (
            "---\n\n"
            "*Report generated by "
            "[SecurityAutomationToolkit]"
            "(https://github.com/raj469-doit/"
            "SecurityAutomationToolkit)*\n"
        )

        return md

    def generate_html(self, output_path: str) -> None:
        """Write a standalone HTML dashboard to output_path."""
        metrics = self.compile_metrics()
        target = self.findings.get("target", "Unknown")
        score = self.findings.get("final_score", 100)
        grade = _grade_label(score)
        g_color = _grade_color(grade)
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )

        total = metrics["total_vulnerabilities"]
        crit_pct = (
            (metrics["Critical"] / total * 100) if total > 0 else 0
        )
        high_pct = (
            (metrics["High"] / total * 100) if total > 0 else 0
        )
        med_pct = (
            (metrics["Medium"] / total * 100) if total > 0 else 0
        )
        low_pct = (
            (metrics["Low"] / total * 100) if total > 0 else 0
        )

        # Build vulnerability rows sorted by severity
        sorted_vulns = self._sort_vulns_by_severity(
            self.findings.get("vulnerabilities", [])
        )
        vuln_rows = ""
        for vuln in sorted_vulns:
            sev = vuln.get("severity", "Low")
            vuln_rows += (
                f'\n            <tr>'
                f'<td><strong>'
                f'{vuln.get("owasp_category")}</strong></td>'
                f'<td><span class="badge-{sev.lower()}">'
                f'{sev}</span></td>'
                f'<td>{vuln.get("description")}</td>'
                f'<td>{vuln.get("remediation")}</td>'
                f'</tr>'
            )

        # Build remediation checklist rows
        checklist_rows = ""
        for i, vuln in enumerate(sorted_vulns, start=1):
            sev = vuln.get("severity", "Low")
            checklist_rows += (
                f'\n            <tr>'
                f'<td style="text-align:center">{i}</td>'
                f'<td><span class="badge-{sev.lower()}">'
                f'{sev}</span></td>'
                f'<td>{vuln.get("remediation")}</td>'
                f'<td><input type="checkbox"></td>'
                f'</tr>'
            )

        # Build OWASP breakdown rows
        owasp_rows = ""
        for cat, count in sorted(
            metrics["owasp_breakdown"].items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            owasp_rows += (
                f'\n            <tr>'
                f'<td>{cat}</td>'
                f'<td style="text-align:center">{count}</td>'
                f'</tr>'
            )

        # Delta section
        delta_section = ""
        if self.baseline:
            sign = (
                "+" if self.deltas["score_delta"] >= 0 else ""
            )
            n_new = len(self.deltas["new"])
            n_fixed = len(self.deltas["fixed"])

            delta_color = (
                "#10b981"
                if self.deltas["score_delta"] > 0
                else "#ef4444"
                if self.deltas["score_delta"] < 0
                else "#64748b"
            )

            fixed_items = ""
            if self.deltas["fixed"]:
                fixed_items = "".join(
                    f'<li class="text-success">'
                    f'\u2705 {v.get("description")}</li>'
                    for v in self.deltas["fixed"]
                )
                fixed_items = (
                    f'<ul style="margin:8px 0">'
                    f'{fixed_items}</ul>'
                )

            new_items = ""
            if self.deltas["new"]:
                new_items = "".join(
                    f'<li class="text-danger">'
                    f'\u26a0\ufe0f {v.get("description")}</li>'
                    for v in self.deltas["new"]
                )
                new_items = (
                    f'<ul style="margin:8px 0">'
                    f'{new_items}</ul>'
                )

            delta_section = (
                f'<div class="delta-card">'
                f'<h3>Changes Since Last Scan</h3>'
                f'<p>Score change: <strong style="color:'
                f'{delta_color}">'
                f'{sign}{self.deltas["score_delta"]} '
                f'points</strong></p>'
                f'<p>New issues: '
                f'<span class="text-danger">{n_new}</span>'
                f' &nbsp;|&nbsp; '
                f'Fixed: '
                f'<span class="text-success">{n_fixed}'
                f'</span></p>'
                f'{fixed_items}{new_items}'
                f'</div>'
            )

        score_color = (
            "#10b981" if score >= 80
            else "#f59e0b" if score >= 50
            else "#ef4444"
        )

        no_issues = (
            "<tr><td colspan='4' style='text-align:center;"
            " color:#10b981; padding:20px;'>"
            "\u2705 No issues found. Score: 100/100</td></tr>"
        )

        no_checklist = (
            "<tr><td colspan='4' style='text-align:center;"
            " color:#10b981; padding:20px;'>"
            "Nothing to remediate.</td></tr>"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Assessment - {target}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont,
        "Segoe UI", Roboto, Arial, sans-serif;
      margin: 30px; background: #f8fafc; color: #1e293b;
    }}
    .container {{
      background: white; padding: 30px; border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
      max-width: 1100px; margin: 0 auto;
    }}
    h1, h2, h3 {{ color: #0f172a; margin-top: 0; }}
    .header-layout {{
      display: flex; justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #e2e8f0;
      padding-bottom: 20px; margin-bottom: 25px;
    }}
    .header-meta {{ color: #64748b; font-size: 14px; margin: 4px 0; }}
    .score-block {{ text-align: center; }}
    .score {{
      font-size: 36px; font-weight: bold;
      color: {score_color};
    }}
    .grade {{
      font-size: 48px; font-weight: bold;
      color: {g_color}; line-height: 1;
    }}
    .grade-label {{
      font-size: 13px; color: #64748b;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px; margin: 20px 0;
    }}
    .metric-card {{
      background: #f8fafc; padding: 16px;
      border-radius: 8px; text-align: center;
      border: 1px solid #e2e8f0;
    }}
    .metric-value {{
      font-size: 28px; font-weight: bold;
    }}
    .metric-label {{
      font-size: 12px; color: #64748b;
      text-transform: uppercase; margin-top: 4px;
    }}
    .chart-container {{
      background: #e2e8f0; height: 28px; border-radius: 14px;
      display: flex; overflow: hidden; margin: 20px 0;
    }}
    .bar-critical {{ background: #7f1d1d; width: {crit_pct}%; }}
    .bar-high {{ background: #ef4444; width: {high_pct}%; }}
    .bar-med  {{ background: #f59e0b; width: {med_pct}%; }}
    .bar-low  {{ background: #3b82f6; width: {low_pct}%; }}
    .chart-legend {{
      display: flex; gap: 20px; margin-bottom: 20px;
      font-size: 13px; color: #64748b;
    }}
    .legend-dot {{
      display: inline-block; width: 12px; height: 12px;
      border-radius: 50%; margin-right: 6px;
      vertical-align: middle;
    }}
    .delta-card {{
      background: #f1f5f9; padding: 18px; border-radius: 8px;
      border-left: 4px solid #64748b; margin-bottom: 25px;
    }}
    .delta-card ul {{
      list-style: none; padding-left: 0;
    }}
    .delta-card li {{
      padding: 4px 0; font-size: 14px;
    }}
    .text-danger {{ color: #ef4444; font-weight: bold; }}
    .text-success {{ color: #10b981; font-weight: bold; }}
    table {{
      width: 100%; border-collapse: collapse; margin-top: 15px;
    }}
    th, td {{
      padding: 12px 14px; text-align: left;
      border-bottom: 1px solid #e2e8f0;
    }}
    th {{
      background: #f8fafc; color: #64748b;
      font-weight: 600; font-size: 13px;
      text-transform: uppercase; letter-spacing: 0.03em;
    }}
    .badge-critical {{
      color: white; background: #7f1d1d;
      padding: 4px 10px; border-radius: 4px;
      font-size: 12px; font-weight: bold;
    }}
    .badge-high {{
      color: white; background: #ef4444;
      padding: 4px 10px; border-radius: 4px;
      font-size: 12px; font-weight: bold;
    }}
    .badge-medium {{
      color: white; background: #f59e0b;
      padding: 4px 10px; border-radius: 4px;
      font-size: 12px; font-weight: bold;
    }}
    .badge-low {{
      color: white; background: #3b82f6;
      padding: 4px 10px; border-radius: 4px;
      font-size: 12px; font-weight: bold;
    }}
    .section-divider {{
      border: none; border-top: 1px solid #e2e8f0;
      margin: 30px 0;
    }}
    .footer {{
      text-align: center; color: #94a3b8;
      font-size: 12px; margin-top: 30px;
      padding-top: 20px;
      border-top: 1px solid #e2e8f0;
    }}
    .footer a {{ color: #64748b; }}
    input[type="checkbox"] {{
      width: 18px; height: 18px; cursor: pointer;
    }}
    @media print {{
      body {{ margin: 0; background: white; }}
      .container {{ box-shadow: none; }}
      input[type="checkbox"] {{ appearance: none;
        border: 1px solid #94a3b8;
        width: 14px; height: 14px;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-layout">
      <div>
        <h1>Security Assessment</h1>
        <p class="header-meta">
          <strong>Target:</strong> {target}
        </p>
        <p class="header-meta">
          <strong>Scanned:</strong> {timestamp}
        </p>
      </div>
      <div class="score-block">
        <div class="grade">{grade}</div>
        <div class="grade-label">Grade</div>
        <div class="score">{score}/100</div>
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value" style="color:#7f1d1d">
          {metrics['Critical']}</div>
        <div class="metric-label">Critical</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color:#ef4444">
          {metrics['High']}</div>
        <div class="metric-label">High</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color:#f59e0b">
          {metrics['Medium']}</div>
        <div class="metric-label">Medium</div>
      </div>
      <div class="metric-card">
        <div class="metric-value" style="color:#3b82f6">
          {metrics['Low']}</div>
        <div class="metric-label">Low</div>
      </div>
    </div>

    <h2>Severity Breakdown</h2>
    <div class="chart-container">
      <div class="bar-critical" title="Critical"></div>
      <div class="bar-high" title="High"></div>
      <div class="bar-med"  title="Medium"></div>
      <div class="bar-low"  title="Low"></div>
    </div>
    <div class="chart-legend">
      <span><span class="legend-dot"
        style="background:#7f1d1d"></span>Critical</span>
      <span><span class="legend-dot"
        style="background:#ef4444"></span>High</span>
      <span><span class="legend-dot"
        style="background:#f59e0b"></span>Medium</span>
      <span><span class="legend-dot"
        style="background:#3b82f6"></span>Low</span>
    </div>

    {delta_section}

    <h2>OWASP Category Breakdown</h2>
    <table>
      <thead>
        <tr>
          <th>OWASP Category</th>
          <th style="text-align:center">Issues</th>
        </tr>
      </thead>
      <tbody>
        {owasp_rows if owasp_rows else
         "<tr><td colspan='2' style='text-align:center;"
         " color:#10b981'>No issues found.</td></tr>"}
      </tbody>
    </table>

    <hr class="section-divider">

    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>OWASP Category</th>
          <th>Severity</th>
          <th>Description</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {vuln_rows if vuln_rows else no_issues}
      </tbody>
    </table>

    <hr class="section-divider">

    <h2>Remediation Checklist</h2>
    <p style="color:#64748b; font-size:14px;">
      Prioritized by severity. Address Critical and High
      items before deployment.
    </p>
    <table>
      <thead>
        <tr>
          <th style="width:50px; text-align:center">#</th>
          <th style="width:90px">Severity</th>
          <th>Action Required</th>
          <th style="width:60px; text-align:center">Done</th>
        </tr>
      </thead>
      <tbody>
        {checklist_rows if checklist_rows else no_checklist}
      </tbody>
    </table>

    <div class="footer">
      <p>
        Generated by
        <a href="https://github.com/raj469-doit/SecurityAutomationToolkit"
          >SecurityAutomationToolkit</a>
        &nbsp;|&nbsp;
        Robert Johnson &mdash;
        <a href="https://linkedin.com/in/robert-johnson-sdet"
          >linkedin.com/in/robert-johnson-sdet</a>
        &nbsp;|&nbsp;
        Mapped to OWASP Top 10 Web Application
        Security Risks (2021)
      </p>
    </div>
  </div>
</body>
</html>
"""

        try:
            parent = os.path.dirname(output_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(
                output_path, "w", encoding="utf-8"
            ) as f:
                f.write(html_content)
            logger.info(f"HTML report saved: {output_path}")
        except Exception as e:
            logger.error(
                f"Could not write HTML report: {str(e)}"
            )


def create_html_report(
    findings: Dict[str, Any],
    output_path: str = "report.html",
    baseline: Optional[Dict[str, Any]] = None,
) -> None:
    """Convenience wrapper for callers that use the old functional API."""
    ComplianceReporter(
        findings, baseline=baseline
    ).generate_html(output_path)


def main() -> None:
    """
    Run the reporter standalone.

    Usage:
        python generate_report.py \\
            --input scan.json --output reports/dashboard.html
    """
    parser = argparse.ArgumentParser(
        description=(
            "Generate a security report from a scan JSON file"
        ),
    )
    parser.add_argument(
        "--input", required=True,
        help="Path to scan JSON (output of security_score.py)",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path for the HTML report file",
    )
    parser.add_argument(
        "--baseline",
        help=(
            "Path to a previous scan JSON "
            "for comparison (optional)"
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s - %(name)s - "
            "%(levelname)s - %(message)s"
        ),
    )

    with open(args.input, "r", encoding="utf-8") as f:
        findings = json.load(f)

    baseline = None
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, "r", encoding="utf-8") as f:
            baseline = json.load(f)

    reporter = ComplianceReporter(
        findings=findings, baseline=baseline,
    )
    reporter.generate_html(output_path=args.output)

    md_path = args.output.replace(".html", ".md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(reporter.generate_markdown_summary())
    logger.info(f"Markdown summary saved: {md_path}")


if __name__ == "__main__":
    main()
