# ─────────────────────────────────────────────────────────────────────────────
# main.py
#
# Entry point for the drift detector.
# Orchestrates the full scan pipeline:
#   1. Load Terraform state
#   2. Query live AWS resources
#   3. Compare and find drift
#   4. Generate HTML + JSON reports
#   5. Send Slack alert if drift found
#   6. Exit with code 1 if critical drift found (useful for CI/CD gates)
#
# Run:
#   python3 -m scanner.main
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import sys
import requests
from datetime import datetime, timezone

from scanner.config import (
    AWS_REGION,
    SLACK_WEBHOOK_URL,
    SLACK_ALERT_THRESHOLD,
    LOG_LEVEL,
)
from scanner.state_parser import get_terraform_resources, get_resource_ids_by_type
from scanner.aws_scanner import (
    scan_ec2_instances,
    scan_security_groups,
    scan_s3_buckets,
    scan_untagged_resources,
    get_account_id,
)
from scanner.differ import find_all_drift
from scanner.reporter import generate_report, upload_report_to_s3, print_summary


def setup_logging() -> None:
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level  = level,
        format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt= "%Y-%m-%d %H:%M:%S",
    )


def send_slack_alert(drift_items: list, report_url: str | None = None) -> None:
    """Send a Slack alert summarising the drift findings."""
    if not SLACK_WEBHOOK_URL:
        logger = logging.getLogger(__name__)
        logger.info("Slack webhook not configured — skipping alert")
        return

    critical = sum(1 for d in drift_items if d.is_critical())
    warnings = sum(1 for d in drift_items if d.is_warning())

    colour   = "danger" if critical > 0 else "warning"
    title    = f"Cloud Drift Detected — {len(drift_items)} finding(s)"

    # Build a bullet list of findings for the Slack message
    findings_text = "\n".join([
        f"• [{d.severity.upper()}] {d.drift_type}: {d.resource_id} — {d.attribute}"
        for d in drift_items[:10]  # limit to first 10 to avoid huge messages
    ])

    if len(drift_items) > 10:
        findings_text += f"\n...and {len(drift_items) - 10} more findings"

    payload = {
        "username":    "Cloud Drift Detector",
        "icon_emoji":  ":warning:",
        "attachments": [{
            "color":  colour,
            "title":  title,
            "text":   findings_text,
            "fields": [
                {"title": "Critical", "value": str(critical), "short": True},
                {"title": "Warnings", "value": str(warnings), "short": True},
                {"title": "Region",   "value": AWS_REGION,   "short": True},
                {"title": "Time",     "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "short": True},
            ],
            "footer": "cloud-drift-detector",
        }],
    }

    if report_url:
        payload["attachments"][0]["title_link"] = report_url

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data    = json.dumps(payload),
            headers = {"Content-Type": "application/json"},
            timeout = 10,
        )
        if response.status_code == 200:
            logging.getLogger(__name__).info("Slack alert sent successfully")
        else:
            logging.getLogger(__name__).error(f"Slack returned {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.getLogger(__name__).error(f"Failed to send Slack alert: {e}")


def run_scan() -> int:
    """
    Run the full drift scan and return an exit code.

    Returns:
        0 — no drift or only warnings
        1 — critical drift found (useful as a CI/CD gate)
    """
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("  Cloud Drift Detector starting scan")
    logger.info(f"  Region  : {AWS_REGION}")
    logger.info(f"  Account : {get_account_id()}")
    logger.info(f"  Time    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    logger.info("=" * 60)

    # ── Step 1: Load Terraform state ─────────────────────────────────────────
    logger.info("Step 1/4: Loading Terraform state...")
    try:
        tf_resources = get_terraform_resources()
    except FileNotFoundError as e:
        logger.warning("No Terraform state file found — nothing to scan.")
        logger.warning("Run 'terraform apply' to create infrastructure first.")
        print("\n⚠ No state file found — skipping scan.\n")
        return 0

    # ── Step 2: Scan live AWS resources ──────────────────────────────────────
    logger.info("Step 2/4: Scanning live AWS resources...")

    ec2_data = scan_ec2_instances(
        get_resource_ids_by_type(tf_resources, "aws_instance")
    )
    sg_data = scan_security_groups(
        get_resource_ids_by_type(tf_resources, "aws_security_group")
    )
    s3_data = scan_s3_buckets(
        get_resource_ids_by_type(tf_resources, "aws_s3_bucket")
    )
    untagged = scan_untagged_resources()

    total_resources = len(ec2_data) + len(sg_data) + len(s3_data)

    # ── Step 3: Find drift ────────────────────────────────────────────────────
    logger.info("Step 3/4: Comparing state against live resources...")
    drift_items = find_all_drift(tf_resources, ec2_data, sg_data, s3_data, untagged)

    # ── Step 4: Generate reports ──────────────────────────────────────────────
    logger.info("Step 4/4: Generating reports...")
    html_path, json_path = generate_report(drift_items, total_resources)

    # Upload to S3 if configured
    report_url = upload_report_to_s3(html_path)

    # Print to console
    print_summary(drift_items)
    logger.info(f"HTML report: {html_path}")
    logger.info(f"JSON report: {json_path}")
    if report_url:
        logger.info(f"S3 report URL: {report_url}")

    # Send Slack alert if enough drift found
    if len(drift_items) >= SLACK_ALERT_THRESHOLD:
        send_slack_alert(drift_items, report_url)

    # Return exit code — 1 if critical drift, 0 otherwise
    has_critical = any(d.is_critical() for d in drift_items)
    return 1 if has_critical else 0


def main() -> None:
    setup_logging()
    exit_code = run_scan()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
