# ─────────────────────────────────────────────────────────────────────────────
# differ.py
#
# Compares the Terraform state (what should exist) against the live AWS
# account (what actually exists) and produces a list of DriftItem objects.
#
# Each DriftItem describes one piece of drift:
#   - What resource it affects
#   - What type of drift (security, config, ghost, tag)
#   - How severe it is (critical, warning, info)
#   - What the expected value was vs what the actual value is
#
# This is the core logic of the entire project.
# ─────────────────────────────────────────────────────────────────────────────

import logging
from dataclasses import dataclass, field
from typing import Optional

from scanner.config import (
    CRITICAL_CIDR_RANGES,
    CRITICAL_PORTS,
    REQUIRED_TAGS,
    SCAN_EC2_INSTANCES,
    SCAN_S3_BUCKETS,
    SCAN_SECURITY_GROUPS,
    SCAN_UNTAGGED,
)
from scanner.state_parser import TerraformResource

logger = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class DriftItem:
    """
    Represents one detected drift finding.

    drift_type:
        "security" → a security misconfiguration (open ports, public bucket)
        "config"   → a configuration change (wrong instance type, etc.)
        "ghost"    → resource exists in AWS but not in Terraform state
        "tag"      → missing or incorrect required tags

    severity:
        "critical" → immediate security risk, alert now
        "warning"  → deviation from desired state, should fix
        "info"     → informational, low priority

    resource_key:  "aws_instance.web" or the AWS resource ID
    resource_id:   the actual AWS resource ID (e.g. "i-042e826eedb4ef34d")
    attribute:     which attribute drifted (e.g. "instance_type", "port_22")
    expected:      what Terraform/policy says it should be
    actual:        what AWS says it actually is
    message:       human-readable description of the drift
    """
    drift_type:   str
    severity:     str
    resource_key: str
    resource_id:  str
    attribute:    str
    expected:     str
    actual:       str
    message:      str
    # Extra context for the HTML report
    extra:        dict = field(default_factory=dict)

    def is_critical(self) -> bool:
        return self.severity == "critical"

    def is_warning(self) -> bool:
        return self.severity == "warning"


# ── Main differ entry point ───────────────────────────────────────────────────

def find_all_drift(
    tf_resources:  dict[str, TerraformResource],
    ec2_live:      dict[str, dict],
    sg_live:       dict[str, dict],
    s3_live:       dict[str, dict],
    untagged_live: list[dict],
) -> list[DriftItem]:
    """
    Run all drift checks and return the combined list of findings.

    Parameters:
        tf_resources  : parsed Terraform state (from state_parser.py)
        ec2_live      : live EC2 data (from aws_scanner.py)
        sg_live       : live security group data
        s3_live       : live S3 data
        untagged_live : list of resources missing required tags

    Returns:
        list of DriftItem objects, sorted by severity (critical first)
    """
    drift_items = []

    if SCAN_EC2_INSTANCES:
        drift_items.extend(_check_ec2_drift(tf_resources, ec2_live))

    if SCAN_SECURITY_GROUPS:
        drift_items.extend(_check_security_group_drift(tf_resources, sg_live))

    if SCAN_S3_BUCKETS:
        drift_items.extend(_check_s3_drift(tf_resources, s3_live))

    if SCAN_UNTAGGED:
        drift_items.extend(_check_tag_drift(untagged_live))

    # Sort: critical first, then warning, then info
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    drift_items.sort(key=lambda x: severity_order.get(x.severity, 3))

    critical = sum(1 for d in drift_items if d.is_critical())
    warnings = sum(1 for d in drift_items if d.is_warning())
    logger.info(
        f"Drift detection complete: {len(drift_items)} finding(s) "
        f"({critical} critical, {warnings} warning)"
    )

    return drift_items


# ── EC2 drift checks ──────────────────────────────────────────────────────────

def _check_ec2_drift(
    tf_resources: dict[str, TerraformResource],
    ec2_live:     dict[str, dict],
) -> list[DriftItem]:
    """
    Compare EC2 instances between Terraform state and live AWS.

    Checks:
    1. Instance type changed (e.g. t3.micro → t3.small)
    2. Instance terminated outside Terraform (ghost deletion)
    3. Instance stopped when it should be running
    """
    findings = []

    # Find all EC2 instances in Terraform state
    ec2_resources = {
        k: v for k, v in tf_resources.items()
        if v.resource_type == "aws_instance"
    }

    for resource_key, tf_resource in ec2_resources.items():
        instance_id = tf_resource.resource_id
        live = ec2_live.get(instance_id)

        # ── Check 1: Instance doesn't exist in AWS anymore ───────────────────
        if not live:
            findings.append(DriftItem(
                drift_type   = "ghost",
                severity     = "critical",
                resource_key = resource_key,
                resource_id  = instance_id,
                attribute    = "existence",
                expected     = "running",
                actual       = "not found",
                message      = (
                    f"EC2 instance {instance_id} exists in Terraform state "
                    f"but was not found in AWS. It may have been manually "
                    f"terminated."
                ),
            ))
            continue

        # ── Check 2: Instance type changed ───────────────────────────────────
        tf_type   = tf_resource.get("instance_type")
        live_type = live.get("instance_type")

        if tf_type and live_type and tf_type != live_type:
            findings.append(DriftItem(
                drift_type   = "config",
                severity     = "warning",
                resource_key = resource_key,
                resource_id  = instance_id,
                attribute    = "instance_type",
                expected     = tf_type,
                actual       = live_type,
                message      = (
                    f"EC2 instance type changed from {tf_type} to {live_type}. "
                    f"This was likely done manually in the console."
                ),
            ))

        # ── Check 3: Instance stopped ─────────────────────────────────────────
        live_state = live.get("state")
        if live_state and live_state not in ("running", "pending"):
            findings.append(DriftItem(
                drift_type   = "config",
                severity     = "warning",
                resource_key = resource_key,
                resource_id  = instance_id,
                attribute    = "state",
                expected     = "running",
                actual       = live_state,
                message      = (
                    f"EC2 instance {instance_id} is in state '{live_state}' "
                    f"instead of 'running'."
                ),
            ))

    return findings


# ── Security group drift checks ───────────────────────────────────────────────

def _check_security_group_drift(
    tf_resources: dict[str, TerraformResource],
    sg_live:      dict[str, dict],
) -> list[DriftItem]:
    """
    Check security groups for dangerous rule additions.

    This is the most security-critical check. We look for:
    1. Any inbound rule allowing traffic from 0.0.0.0/0 on critical ports
    2. Rules that weren't in the Terraform state (manually added)

    Why this matters: adding port 22 to 0.0.0.0/0 "just temporarily"
    is one of the most common ways AWS resources get compromised.
    """
    findings = []

    sg_resources = {
        k: v for k, v in tf_resources.items()
        if v.resource_type == "aws_security_group"
    }

    for resource_key, tf_resource in sg_resources.items():
        sg_id = tf_resource.resource_id
        live  = sg_live.get(sg_id)

        if not live:
            findings.append(DriftItem(
                drift_type   = "ghost",
                severity     = "critical",
                resource_key = resource_key,
                resource_id  = sg_id,
                attribute    = "existence",
                expected     = "exists",
                actual       = "not found",
                message      = f"Security group {sg_id} not found in AWS.",
            ))
            continue

        # Check each live ingress rule for dangerous patterns
        for rule in live.get("ingress_rules", []):
            cidr     = rule.get("cidr", "")
            from_port = rule.get("from_port", 0)
            to_port   = rule.get("to_port", 0)
            protocol  = rule.get("protocol", "")

            # Is this rule open to the entire internet?
            is_open_to_internet = cidr in CRITICAL_CIDR_RANGES

            if not is_open_to_internet:
                continue

            # Allow-listed ports: 80 (HTTP) and 443 (HTTPS) open to internet
            # are intentional for a web server — don't flag these
            allowed_public_ports = {80, 443}

            # Check if any critical port is in the range from_port..to_port
            for critical_port in CRITICAL_PORTS:
                if critical_port in allowed_public_ports:
                    continue

                # Port range check: from_port=0, to_port=0 means all ports (-1 protocol)
                port_in_range = (
                    protocol == "-1" or  # all traffic
                    (from_port <= critical_port <= to_port)
                )

                if port_in_range:
                    port_names = {
                        22: "SSH", 3389: "RDP", 3306: "MySQL",
                        5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"
                    }
                    port_label = port_names.get(critical_port, str(critical_port))

                    findings.append(DriftItem(
                        drift_type   = "security",
                        severity     = "critical",
                        resource_key = resource_key,
                        resource_id  = sg_id,
                        attribute    = f"ingress_port_{critical_port}",
                        expected     = f"port {critical_port} ({port_label}) not exposed to internet",
                        actual       = f"port {critical_port} ({port_label}) open to {cidr}",
                        message      = (
                            f"SECURITY: {port_label} (port {critical_port}) is open to "
                            f"{cidr} on security group {sg_id}. "
                            f"This is a critical security misconfiguration."
                        ),
                        extra        = {"rule": rule},
                    ))

    return findings


# ── S3 drift checks ───────────────────────────────────────────────────────────

def _check_s3_drift(
    tf_resources: dict[str, TerraformResource],
    s3_live:      dict[str, dict],
) -> list[DriftItem]:
    """
    Check S3 buckets for security and configuration drift.

    Checks:
    1. Public access block disabled (critical — data breach risk)
    2. Versioning disabled (warning)
    3. Encryption disabled (warning)
    """
    findings = []

    s3_resources = {
        k: v for k, v in tf_resources.items()
        if v.resource_type == "aws_s3_bucket"
    }

    for resource_key, tf_resource in s3_resources.items():
        bucket_name = tf_resource.resource_id
        live = s3_live.get(bucket_name)

        if not live:
            continue

        if not live.get("exists", True):
            findings.append(DriftItem(
                drift_type   = "ghost",
                severity     = "critical",
                resource_key = resource_key,
                resource_id  = bucket_name,
                attribute    = "existence",
                expected     = "exists",
                actual       = "deleted",
                message      = (
                    f"S3 bucket {bucket_name} exists in Terraform state "
                    f"but was deleted in AWS."
                ),
            ))
            continue

        # ── Check 1: Public access block ─────────────────────────────────────
        pab = live.get("public_access_block", {})
        if pab and not pab.get("block_public_acls", True):
            findings.append(DriftItem(
                drift_type   = "security",
                severity     = "critical",
                resource_key = resource_key,
                resource_id  = bucket_name,
                attribute    = "public_access_block",
                expected     = "all public access blocked",
                actual       = "public access NOT fully blocked",
                message      = (
                    f"SECURITY: S3 bucket {bucket_name} has public access "
                    f"enabled. Data in this bucket may be publicly accessible."
                ),
                extra        = {"public_access_block": pab},
            ))

        # ── Check 2: Versioning ───────────────────────────────────────────────
        live_versioning = live.get("versioning")
        if live_versioning and live_versioning != "Enabled":
            findings.append(DriftItem(
                drift_type   = "config",
                severity     = "warning",
                resource_key = resource_key,
                resource_id  = bucket_name,
                attribute    = "versioning",
                expected     = "Enabled",
                actual       = live_versioning or "Disabled",
                message      = (
                    f"S3 bucket {bucket_name} versioning is '{live_versioning}'. "
                    f"Terraform set it to 'Enabled'. Versioning protects against "
                    f"accidental deletion."
                ),
            ))

        # ── Check 3: Encryption ───────────────────────────────────────────────
        enc = live.get("encryption", {})
        if enc and not enc.get("enabled", True):
            findings.append(DriftItem(
                drift_type   = "config",
                severity     = "warning",
                resource_key = resource_key,
                resource_id  = bucket_name,
                attribute    = "encryption",
                expected     = "AES256 server-side encryption enabled",
                actual       = "encryption disabled",
                message      = (
                    f"S3 bucket {bucket_name} server-side encryption has been "
                    f"disabled. Terraform configured AES256 encryption."
                ),
            ))

    return findings


# ── Tag drift checks ──────────────────────────────────────────────────────────

def _check_tag_drift(untagged_resources: list[dict]) -> list[DriftItem]:
    """
    Convert untagged resource findings into DriftItems.

    Resources missing "ManagedBy: terraform" are likely ghost resources
    (created manually outside Terraform). Other missing tags are warnings.
    """
    findings = []

    for resource in untagged_resources:
        resource_id  = resource["resource_id"]
        missing_tags = resource["missing_tags"]
        resource_type = resource["resource_type"]

        # Missing "ManagedBy" tag is the most significant —
        # it suggests the resource wasn't created by Terraform at all
        severity = "critical" if "ManagedBy" in missing_tags else "warning"

        findings.append(DriftItem(
            drift_type   = "tag",
            severity     = severity,
            resource_key = f"{resource_type}.unmanaged",
            resource_id  = resource_id,
            attribute    = "tags",
            expected     = f"tags: {', '.join(REQUIRED_TAGS)}",
            actual       = f"missing: {', '.join(missing_tags)}",
            message      = (
                f"{resource_type} {resource_id} is missing required tags: "
                f"{', '.join(missing_tags)}. "
                f"{'This resource may not be managed by Terraform.' if 'ManagedBy' in missing_tags else ''}"
            ),
            extra        = {
                "missing_tags":  missing_tags,
                "existing_tags": resource.get("existing_tags", {}),
            },
        ))

    return findings
