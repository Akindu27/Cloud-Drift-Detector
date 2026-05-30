# ─────────────────────────────────────────────────────────────────────────────
# config.py
#
# Single source of truth for the entire drift detector.
# Every AWS region, resource tag, severity rule, and alert setting lives here.
# Change behaviour here — nowhere else.
# ─────────────────────────────────────────────────────────────────────────────

import os

# ── AWS settings ──────────────────────────────────────────────────────────────
# The region where your Terraform infrastructure lives.
# ap-southeast-1 = Singapore, closest to Sri Lanka.
# boto3 also reads AWS_DEFAULT_REGION from environment — this is the fallback.
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-1")

# Your AWS account ID — used to construct ARNs and filter resources.
# Fetched automatically at runtime via STS, but can be overridden here.
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", None)

# ── Terraform state settings ──────────────────────────────────────────────────
# Where the Terraform state file lives.
# LOCAL  → reads terraform/terraform.tfstate directly (development)
# REMOTE → reads from S3 (production / GitHub Actions)
STATE_BACKEND = os.environ.get("STATE_BACKEND", "local")

# Path to the local state file (used when STATE_BACKEND = "local")
LOCAL_STATE_PATH = os.environ.get(
    "LOCAL_STATE_PATH",
    "terraform/terraform.tfstate"
)

# S3 bucket and key for remote state (used when STATE_BACKEND = "remote")
STATE_S3_BUCKET = os.environ.get("STATE_S3_BUCKET", "")
STATE_S3_KEY    = os.environ.get("STATE_S3_KEY", "terraform.tfstate")

# ── Resources to scan ─────────────────────────────────────────────────────────
# Which AWS resource types the scanner checks.
# Set any to False to skip that resource type during a scan.
SCAN_EC2_INSTANCES    = True
SCAN_S3_BUCKETS       = True
SCAN_SECURITY_GROUPS  = True
SCAN_IAM_ROLES        = True
SCAN_UNTAGGED         = True   # flag any resource missing required tags

# ── Required tags ─────────────────────────────────────────────────────────────
# Every resource managed by Terraform should have these tags.
# Any resource missing one or more of these is flagged as tag drift.
# "ManagedBy" = "terraform" is the most important — it's how you know
# if something was created outside Terraform.
REQUIRED_TAGS = [
    "ManagedBy",
    "Environment",
    "Project",
]

# ── Drift severity rules ──────────────────────────────────────────────────────
# Rules that determine severity levels.
# CRITICAL → immediate Slack alert, shown in red on the HTML report
# WARNING  → shown in amber on the HTML report
# INFO     → shown in blue, informational only

# Security group rules that make a finding CRITICAL
CRITICAL_CIDR_RANGES = [
    "0.0.0.0/0",   # open to the entire internet (IPv4)
    "::/0",        # open to the entire internet (IPv6)
]

# Ports that are CRITICAL if exposed to the internet
CRITICAL_PORTS = [
    22,    # SSH
    3389,  # RDP
    3306,  # MySQL
    5432,  # PostgreSQL
    27017, # MongoDB
    6379,  # Redis
]

# ── Report settings ───────────────────────────────────────────────────────────
# Where generated reports are saved locally before being uploaded to S3.
REPORT_OUTPUT_DIR = "reports"

# S3 bucket where HTML reports are uploaded (can be the same as state bucket)
REPORT_S3_BUCKET = os.environ.get("REPORT_S3_BUCKET", "")
REPORT_S3_PREFIX = "drift-reports"

# ── Slack alerting ────────────────────────────────────────────────────────────
# Paste your Slack Incoming Webhook URL here or set as environment variable.
# Leave empty to disable Slack alerts (console output only during development).
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Only send Slack alert if at least this many drift items are found.
# Prevents noise from minor tag drift on every scan.
SLACK_ALERT_THRESHOLD = 1

# ── Scan behaviour ────────────────────────────────────────────────────────────
# How many boto3 API calls to make concurrently.
# Keep low to avoid AWS throttling on free tier accounts.
MAX_WORKERS = 3

# How long to wait for a boto3 API call before timing out (seconds)
BOTO3_TIMEOUT = 30

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
