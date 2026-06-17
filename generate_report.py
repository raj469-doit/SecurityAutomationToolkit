import os
import html
import json
import logging

logger = logging.getLogger(__name__)

def generate_production_report(scan_results, output_path="reports/security_report.html"):
    """
    Builds a clean, standard-compliant HTML5 metrics report.
    Guarantees XSS mitigation and file write operations isolation.
    """
    # PROD-READY: Ensure execution paths exist cleanly without raising collision errors
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # PROD-READY: Escape target data points before embedding to safely kill Stored XSS opportunities
    clean_url = html.escape(scan_results.get("url", "Unknown Target"))
    overall_score = int(scan_results.get("score", 0))
    
    # Color condition based on risk profiles
    score_color = "green" if overall_score >= 80 else "orange" if overall_score >= 50 else "red"
    
    # Construct structured HTML5 template
    html_markup = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Framework Report Summary</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; margin: 40px; color: #333; }}
        .metric-badge {{ font-size: 24px; font-weight: bold; color: {score_color}; }}
        .vulnerability-list {{ background: #f9f9f9; padding: 15px; border-left: 4px solid #d9534f; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <h1>OWASP Assessment Report</h1>
    <p>Target System: <strong>{clean_url}</strong></p>
    <p>Compliance Score: <span class="metric-badge">{overall_score}/100</span></p>
    
    <h2>Identified Compliance Deviations</h2>
"""
    
    if scan_results.get("missing_headers"):
        html_markup += "<div class='vulnerability-list'><h3>Missing Security Headers:</h3><ul>"
        for missing in scan_results["missing_headers"]:
            html_markup += f"<li>{html.escape(missing)}</li>"
        html_markup += "</ul></div>"
        
    if scan_results.get("errors"):
        html_markup += "<div class='vulnerability-list' style='border-left-color: #f0ad4e;'><h3>Execution Errors:</h3><ul>"
        for err in scan_results["errors"]:
            html_markup += f"<li>{html.escape(str(err))}</li>"
        html_markup += "</ul></div>"

    html_markup += """
</body>
</html>
"""

    # PROD-READY: Atomic Write Pattern
    # This mitigates file corruption risks if the process runs out of disk space or receives a SIGKILL mid-operation.
    tmp_file_path = f"{output_path}.tmp"
    try:
        with open(tmp_file_path, "w", encoding="utf-8") as file_stream:
            file_stream.write(html_markup)
        
        # Atomically replace the target production file path
        os.replace(tmp_file_path, output_path)
        logger.info(f"Production safety report mapped cleanly to output stream: {output_path}")
        
    except IOError as io_error:
        logger.error(f"Failed to generate output file write operations at destination: {output_path}. Error: {io_error}")
        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
        raise io_error
