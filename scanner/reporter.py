# ─────────────────────────────────────────────────────────────────────────────
# reporter.py
#
# Takes the list of DriftItem objects from differ.py and produces:
#   1. A colour-coded HTML report saved to reports/ and optionally to S3
#   2. A JSON summary for programmatic use and Slack alerts
#
# Uses Jinja2 for HTML templating — same engine Django and Flask use.
# The template is defined inline as a string to keep the project self-contained.
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import os
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Template

from scanner.config import (
    REPORT_OUTPUT_DIR,
    REPORT_S3_BUCKET,
    REPORT_S3_PREFIX,
    AWS_REGION,
)
from scanner.differ import DriftItem

logger = logging.getLogger(__name__)

# ── HTML template ─────────────────────────────────────────────────────────────
# Inline Jinja2 template — no external files needed.
# {{ variable }} = output a variable
# {% if %} / {% for %} = control flow
# | e = escape HTML special characters (security best practice)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloud Drift Report — {{ scan_time }}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f5f5f5; color: #333; padding: 2rem; }
    .container { max-width: 1100px; margin: 0 auto; }
    header { background: #1a1a2e; color: white; padding: 2rem;
             border-radius: 8px; margin-bottom: 2rem; }
    header h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
    header p  { color: #aaa; font-size: 0.9rem; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr);
             gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: white; border-radius: 8px; padding: 1.25rem;
                 text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .stat-card .number { font-size: 2.5rem; font-weight: 700; }
    .stat-card .label  { font-size: 0.85rem; color: #666; margin-top: 0.25rem; }
    .critical { color: #e53e3e; }
    .warning  { color: #dd6b20; }
    .info     { color: #3182ce; }
    .clean    { color: #38a169; }
    .findings { background: white; border-radius: 8px; padding: 1.5rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .findings h2 { font-size: 1.2rem; margin-bottom: 1rem; color: #444; }
    .finding-card { border: 1px solid #e2e8f0; border-radius: 6px;
                    padding: 1rem; margin-bottom: 1rem; }
    .finding-card.critical { border-left: 4px solid #e53e3e; background: #fff5f5; }
    .finding-card.warning  { border-left: 4px solid #dd6b20; background: #fffaf0; }
    .finding-card.info     { border-left: 4px solid #3182ce; background: #ebf8ff; }
    .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge.critical { background: #e53e3e; color: white; }
    .badge.warning  { background: #dd6b20; color: white; }
    .badge.info     { background: #3182ce; color: white; }
    .badge.type     { background: #e2e8f0; color: #444; }
    .resource-id    { font-family: monospace; font-size: 0.85rem; color: #666; }
    .message        { font-size: 0.9rem; color: #444; margin: 0.5rem 0; }
    .diff-row       { display: flex; gap: 1rem; margin-top: 0.5rem; font-size: 0.85rem; }
    .diff-box       { flex: 1; padding: 0.5rem 0.75rem; border-radius: 4px; }
    .diff-expected  { background: #e6ffed; border: 1px solid #b7e1c4; color: #276749; }
    .diff-actual    { background: #fff5f5; border: 1px solid #fed7d7; color: #c53030; }
    .diff-label     { font-weight: 600; margin-bottom: 2px; }
    .no-drift       { text-align: center; padding: 3rem; color: #38a169; }
    .no-drift .icon { font-size: 3rem; margin-bottom: 1rem; }
    footer { text-align: center; color: #aaa; font-size: 0.8rem; margin-top: 2rem; }
  </style>
</head>
<body>
<div class="container">

  <header>
    <h1>Cloud Infrastructure Drift Report</h1>
    <p>Generated: {{ scan_time }} UTC &nbsp;|&nbsp;
       Region: {{ aws_region }} &nbsp;|&nbsp;
       Resources scanned: {{ total_resources }}</p>
  </header>

  <div class="stats">
    <div class="stat-card">
      <div class="number {% if total_findings > 0 %}critical{% else %}clean{% endif %}">
        {{ total_findings }}
      </div>
      <div class="label">Total findings</div>
    </div>
    <div class="stat-card">
      <div class="number {% if critical_count > 0 %}critical{% endif %}">
        {{ critical_count }}
      </div>
      <div class="label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="number {% if warning_count > 0 %}warning{% endif %}">
        {{ warning_count }}
      </div>
      <div class="label">Warnings</div>
    </div>
    <div class="stat-card">
      <div class="number clean">{{ total_resources }}</div>
      <div class="label">Resources checked</div>
    </div>
  </div>

  <div class="findings">
    {% if drift_items %}
      <h2>Drift findings (sorted by severity)</h2>
      {% for item in drift_items %}
      <div class="finding-card {{ item.severity }}">
        <div class="finding-header">
          <span class="badge {{ item.severity }}">{{ item.severity }}</span>
          <span class="badge type">{{ item.drift_type }}</span>
          <span class="resource-id">{{ item.resource_id | e }}</span>
        </div>
        <div class="message">{{ item.message | e }}</div>
        <div class="diff-row">
          <div class="diff-box diff-expected">
            <div class="diff-label">Expected (Terraform)</div>
            {{ item.expected | e }}
          </div>
          <div class="diff-box diff-actual">
            <div class="diff-label">Actual (AWS)</div>
            {{ item.actual | e }}
          </div>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <div class="no-drift">
        <div class="icon">✓</div>
        <h2>No drift detected</h2>
        <p>All resources match their Terraform definitions.</p>
      </div>
    {% endif %}
  </div>

  <footer>
    Cloud Drift Detector &nbsp;|&nbsp;
    Built by Akindu Gunarathna &nbsp;|&nbsp;
    github.com/Akindu27/cloud-drift-detector
  </footer>

</div>
</body>
</html>
"""


# ── Report generation ─────────────────────────────────────────────────────────

def generate_report(
    drift_items:     list[DriftItem],
    total_resources: int,
    aws_region:      str = AWS_REGION,
) -> tuple[str, str]:
    """
    Generate HTML and JSON reports from a list of DriftItems.

    Returns:
        (html_path, json_path) — paths to the saved report files

    The HTML report is human-readable, colour-coded, and suitable for
    sharing with a team or saving as a static site on S3.

    The JSON report is machine-readable — useful for piping into other
    tools or storing historical scan results.
    """
    # Ensure the output directory exists
    output_dir = Path(REPORT_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Timestamp for file naming and report header
    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # ── Generate HTML ─────────────────────────────────────────────────────────
    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        scan_time        = scan_time,
        aws_region       = aws_region,
        total_resources  = total_resources,
        total_findings   = len(drift_items),
        critical_count   = sum(1 for d in drift_items if d.is_critical()),
        warning_count    = sum(1 for d in drift_items if d.is_warning()),
        drift_items      = drift_items,
    )

    html_path = output_dir / f"drift_report_{timestamp}.html"
    html_path.write_text(html_content, encoding="utf-8")
    logger.info(f"HTML report saved to {html_path}")

    # ── Generate JSON ─────────────────────────────────────────────────────────
    json_data = {
        "scan_time":       scan_time,
        "aws_region":      aws_region,
        "total_resources": total_resources,
        "total_findings":  len(drift_items),
        "critical_count":  sum(1 for d in drift_items if d.is_critical()),
        "warning_count":   sum(1 for d in drift_items if d.is_warning()),
        "findings": [
            {
                "drift_type":   item.drift_type,
                "severity":     item.severity,
                "resource_key": item.resource_key,
                "resource_id":  item.resource_id,
                "attribute":    item.attribute,
                "expected":     item.expected,
                "actual":       item.actual,
                "message":      item.message,
            }
            for item in drift_items
        ],
    }

    json_path = output_dir / f"drift_report_{timestamp}.json"
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    logger.info(f"JSON report saved to {json_path}")

    return str(html_path), str(json_path)


def upload_report_to_s3(html_path: str) -> str | None:
    """
    Upload the HTML report to S3 as a static website file.

    Returns the S3 URL if successful, None if upload fails or not configured.

    The report is publicly readable so you can share the URL with your team.
    In production you'd use CloudFront + private S3 instead.
    """
    if not REPORT_S3_BUCKET:
        logger.info("REPORT_S3_BUCKET not set — skipping S3 upload")
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    s3_key = f"{REPORT_S3_PREFIX}/drift_report_{timestamp}.html"

    try:
        s3 = boto3.client("s3", region_name=AWS_REGION)
        s3.upload_file(
            Filename     = html_path,
            Bucket       = REPORT_S3_BUCKET,
            Key          = s3_key,
            ExtraArgs    = {
                "ContentType": "text/html",
                # Makes the file readable in a browser
                "ContentDisposition": "inline",
            },
        )

        url = f"https://{REPORT_S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
        logger.info(f"Report uploaded to {url}")
        return url

    except ClientError as e:
        logger.error(f"Failed to upload report to S3: {e}")
        return None


def print_summary(drift_items: list[DriftItem]) -> None:
    """
    Print a clean summary to the console.
    Used when running the scanner manually from the terminal.
    """
    if not drift_items:
        print("\n✓ No drift detected — infrastructure matches Terraform state.\n")
        return

    critical = [d for d in drift_items if d.is_critical()]
    warnings = [d for d in drift_items if d.is_warning()]

    print(f"\n{'='*60}")
    print(f"  DRIFT REPORT: {len(drift_items)} finding(s)")
    print(f"  Critical: {len(critical)}  |  Warnings: {len(warnings)}")
    print(f"{'='*60}\n")

    for item in drift_items:
        icon = "🔴" if item.is_critical() else "🟡" if item.is_warning() else "🔵"
        print(f"{icon} [{item.severity.upper()}] {item.drift_type.upper()}")
        print(f"   Resource : {item.resource_id}")
        print(f"   Attribute: {item.attribute}")
        print(f"   Expected : {item.expected}")
        print(f"   Actual   : {item.actual}")
        print(f"   Message  : {item.message}")
        print()
