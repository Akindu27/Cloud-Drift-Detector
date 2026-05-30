# ─────────────────────────────────────────────────────────────────────────────
# aws_scanner.py
#
# Queries the live AWS account via boto3 and returns the current state
# of every resource the drift detector monitors.
#
# Each function returns a dict of resource_id -> attributes.
# The differ.py then compares these against the Terraform state.
#
# boto3 concept:
#   boto3.client("ec2") creates an API client for the EC2 service.
#   client.describe_instances() calls the EC2 API and returns JSON.
#   The response structure mirrors the AWS API — always check the docs:
#   https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html
# ─────────────────────────────────────────────────────────────────────────────

import logging
import boto3
from botocore.exceptions import ClientError, EndpointResolutionError

from scanner.config import (
    AWS_REGION,
    SCAN_EC2_INSTANCES,
    SCAN_S3_BUCKETS,
    SCAN_SECURITY_GROUPS,
)

logger = logging.getLogger(__name__)


# ── boto3 client factory ──────────────────────────────────────────────────────

def _get_client(service: str):
    """
    Create a boto3 client for the given AWS service.

    Centralising client creation here means:
    - Tests can mock this one function to intercept all AWS calls
    - Region is always consistent (from config)
    - Easy to add retry logic or custom endpoints later
    """
    return boto3.client(service, region_name=AWS_REGION)


# ── EC2 scanner ───────────────────────────────────────────────────────────────

def scan_ec2_instances(instance_ids: list[str]) -> dict[str, dict]:
    """
    Fetch current attributes for a list of EC2 instance IDs.

    Returns:
        dict mapping instance_id -> current attributes dict
        e.g. {"i-042e826eedb4ef34d": {"instance_type": "t3.micro", "state": "running", ...}}

    We only fetch the specific instance IDs from the Terraform state.
    This is more efficient than listing all instances in the account,
    and avoids flagging unrelated instances as drift.
    """
    if not instance_ids or not SCAN_EC2_INSTANCES:
        return {}

    logger.info(f"Scanning {len(instance_ids)} EC2 instance(s): {instance_ids}")
    ec2 = _get_client("ec2")
    results = {}

    try:
        # describe_instances accepts a list of IDs and returns their current state
        response = ec2.describe_instances(InstanceIds=instance_ids)

        # Response structure: Reservations > Instances (EC2's legacy grouping)
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]

                # Flatten the key attributes we care about for drift detection
                results[instance_id] = {
                    "instance_id":    instance_id,
                    "instance_type":  instance.get("InstanceType"),
                    "state":          instance.get("State", {}).get("Name"),
                    "ami_id":         instance.get("ImageId"),
                    "subnet_id":      instance.get("SubnetId"),
                    "vpc_id":         instance.get("VpcId"),
                    "public_ip":      instance.get("PublicIpAddress"),
                    "private_ip":     instance.get("PrivateIpAddress"),
                    "key_name":       instance.get("KeyName"),
                    "tags":           _parse_tags(instance.get("Tags", [])),
                    "security_groups": [
                        sg["GroupId"] for sg in instance.get("SecurityGroups", [])
                    ],
                    # EBS root volume details
                    "root_volume": _get_root_volume(instance),
                }

                logger.debug(
                    f"EC2 {instance_id}: type={results[instance_id]['instance_type']} "
                    f"state={results[instance_id]['state']}"
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidInstanceID.NotFound":
            # Instance was terminated outside Terraform — this is ghost resource drift
            logger.warning(f"EC2 instance(s) not found: {instance_ids} — may have been manually terminated")
        else:
            logger.error(f"EC2 API error: {e}")

    return results


def _get_root_volume(instance: dict) -> dict:
    """Extract root EBS volume details from an instance response."""
    for mapping in instance.get("BlockDeviceMappings", []):
        if mapping.get("DeviceName") == instance.get("RootDeviceName"):
            ebs = mapping.get("Ebs", {})
            return {
                "volume_id":  ebs.get("VolumeId"),
                "delete_on_termination": ebs.get("DeleteOnTermination"),
            }
    return {}


# ── Security group scanner ────────────────────────────────────────────────────

def scan_security_groups(sg_ids: list[str]) -> dict[str, dict]:
    """
    Fetch current rules for a list of security group IDs.

    This is the most important scan for security drift detection.
    We capture every inbound rule so the differ can check for
    dangerous ports open to 0.0.0.0/0.

    Returns:
        dict mapping sg_id -> current attributes including all ingress rules
    """
    if not sg_ids or not SCAN_SECURITY_GROUPS:
        return {}

    logger.info(f"Scanning {len(sg_ids)} security group(s): {sg_ids}")
    ec2 = _get_client("ec2")
    results = {}

    try:
        response = ec2.describe_security_groups(GroupIds=sg_ids)

        for sg in response.get("SecurityGroups", []):
            sg_id = sg["GroupId"]

            # Parse each ingress rule into a clean, comparable format
            ingress_rules = []
            for rule in sg.get("IpPermissions", []):
                # Each rule can have multiple IP ranges
                for ip_range in rule.get("IpRanges", []):
                    ingress_rules.append({
                        "from_port": rule.get("FromPort", 0),
                        "to_port":   rule.get("ToPort",   0),
                        "protocol":  rule.get("IpProtocol", "-1"),
                        "cidr":      ip_range.get("CidrIp", ""),
                        "description": ip_range.get("Description", ""),
                    })

                # Also check IPv6 ranges
                for ip_range in rule.get("Ipv6Ranges", []):
                    ingress_rules.append({
                        "from_port": rule.get("FromPort", 0),
                        "to_port":   rule.get("ToPort",   0),
                        "protocol":  rule.get("IpProtocol", "-1"),
                        "cidr":      ip_range.get("CidrIpv6", ""),
                        "description": ip_range.get("Description", ""),
                    })

            results[sg_id] = {
                "sg_id":         sg_id,
                "name":          sg.get("GroupName"),
                "description":   sg.get("Description"),
                "vpc_id":        sg.get("VpcId"),
                "ingress_rules": ingress_rules,
                "tags":          _parse_tags(sg.get("Tags", [])),
            }

            logger.debug(
                f"Security group {sg_id}: {len(ingress_rules)} ingress rule(s)"
            )

    except ClientError as e:
        logger.error(f"Security group API error: {e}")

    return results


# ── S3 scanner ────────────────────────────────────────────────────────────────

def scan_s3_buckets(bucket_names: list[str]) -> dict[str, dict]:
    """
    Fetch current security and configuration attributes for S3 buckets.

    Checks:
    - Public access block settings (is the bucket accidentally public?)
    - Versioning status (is versioning enabled as Terraform defined?)
    - Encryption (is server-side encryption still enabled?)
    - Tags (are required tags present?)

    S3 is region-less at the API level but bucket-specific calls
    need to go to the right region, which boto3 handles automatically.
    """
    if not bucket_names or not SCAN_S3_BUCKETS:
        return {}

    logger.info(f"Scanning {len(bucket_names)} S3 bucket(s): {bucket_names}")
    s3 = _get_client("s3")
    results = {}

    for bucket_name in bucket_names:
        bucket_data = {
            "bucket_name":          bucket_name,
            "public_access_block":  None,
            "versioning":           None,
            "encryption":           None,
            "tags":                 {},
            "exists":               True,
        }

        try:
            # ── Public access block ──────────────────────────────────────────
            # This is the most important S3 security check.
            # A bucket with public access enabled is a common misconfiguration
            # that has caused many high-profile data breaches.
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                bucket_data["public_access_block"] = {
                    "block_public_acls":       config.get("BlockPublicAcls", False),
                    "block_public_policy":     config.get("BlockPublicPolicy", False),
                    "ignore_public_acls":      config.get("IgnorePublicAcls", False),
                    "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
                }
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    # No public access block configured at all — bucket may be public
                    bucket_data["public_access_block"] = {
                        "block_public_acls":       False,
                        "block_public_policy":     False,
                        "ignore_public_acls":      False,
                        "restrict_public_buckets": False,
                    }
                    logger.warning(f"S3 {bucket_name}: no public access block — bucket may be public")

            # ── Versioning ────────────────────────────────────────────────────
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                bucket_data["versioning"] = versioning.get("Status", "Disabled")
            except ClientError as e:
                logger.warning(f"S3 {bucket_name}: could not get versioning: {e}")

            # ── Encryption ────────────────────────────────────────────────────
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    default = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    bucket_data["encryption"] = {
                        "enabled":       True,
                        "sse_algorithm": default.get("SSEAlgorithm", ""),
                    }
                else:
                    bucket_data["encryption"] = {"enabled": False, "sse_algorithm": ""}
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    bucket_data["encryption"] = {"enabled": False, "sse_algorithm": ""}
                else:
                    logger.warning(f"S3 {bucket_name}: could not get encryption: {e}")

            # ── Tags ──────────────────────────────────────────────────────────
            try:
                tagging = s3.get_bucket_tagging(Bucket=bucket_name)
                bucket_data["tags"] = _parse_tags(tagging.get("TagSet", []))
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    bucket_data["tags"] = {}
                else:
                    logger.warning(f"S3 {bucket_name}: could not get tags: {e}")

            results[bucket_name] = bucket_data
            logger.debug(
                f"S3 {bucket_name}: "
                f"public={not bucket_data['public_access_block']['block_public_acls']} "
                f"versioning={bucket_data['versioning']} "
                f"encrypted={bucket_data['encryption']['enabled'] if bucket_data['encryption'] else False}"
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(f"S3 bucket {bucket_name} does not exist — may have been manually deleted")
                bucket_data["exists"] = False
                results[bucket_name] = bucket_data
            else:
                logger.error(f"S3 API error for {bucket_name}: {e}")

    return results


# ── Tag scanner ───────────────────────────────────────────────────────────────

def scan_untagged_resources() -> list[dict]:
    """
    Scan all EC2 instances in the account for missing required tags.

    Unlike the other scanners which check specific resource IDs from state,
    this scanner checks ALL resources in the account. This catches resources
    that were created manually (outside Terraform) and have no tags at all.

    Returns a list of resources missing one or more required tags.
    """
    from scanner.config import REQUIRED_TAGS

    logger.info("Scanning for untagged EC2 resources...")
    ec2 = _get_client("ec2")
    untagged = []

    try:
        # Get all instances in the account (paginate for large accounts)
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    # Skip terminated instances
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue

                    instance_id = instance["InstanceId"]
                    tags = _parse_tags(instance.get("Tags", []))

                    # Check which required tags are missing
                    missing_tags = [
                        tag for tag in REQUIRED_TAGS
                        if tag not in tags
                    ]

                    if missing_tags:
                        untagged.append({
                            "resource_type": "aws_instance",
                            "resource_id":   instance_id,
                            "missing_tags":  missing_tags,
                            "existing_tags": tags,
                        })
                        logger.debug(f"EC2 {instance_id}: missing tags {missing_tags}")

    except ClientError as e:
        logger.error(f"Error scanning for untagged resources: {e}")

    logger.info(f"Found {len(untagged)} resource(s) with missing required tags")
    return untagged


# ── Helper functions ──────────────────────────────────────────────────────────

def _parse_tags(tags: list) -> dict:
    """
    Convert AWS tag format to a plain dict.

    AWS returns tags as: [{"Key": "Name", "Value": "my-server"}, ...]
    We want:            {"Name": "my-server", ...}

    This format is much easier to compare and look up.
    """
    return {tag["Key"]: tag["Value"] for tag in (tags or [])}


def get_account_id() -> str:
    """
    Get the current AWS account ID via STS.
    Used to verify we're scanning the right account.
    """
    try:
        sts = _get_client("sts")
        return sts.get_caller_identity()["Account"]
    except ClientError as e:
        logger.error(f"Could not get account ID: {e}")
        return ""
