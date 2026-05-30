# ─────────────────────────────────────────────────────────────────────────────
# state_parser.py
#
# Reads the Terraform state file (local or from S3) and extracts a clean
# dict of every managed resource with its expected attributes.
#
# The state file is JSON — but its structure is nested and verbose.
# This file's job is to flatten it into a simple format the differ can use:
#
#   {
#     "aws_instance.web": {
#       "id": "i-042e826eedb4ef34d",
#       "instance_type": "t3.micro",
#       "tags": {"ManagedBy": "terraform", ...}
#     },
#     "aws_security_group.web": { ... },
#     ...
#   }
#
# The key is "resource_type.resource_name" — same format Terraform uses.
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import boto3
from pathlib import Path
from typing import Optional

from scanner.config import (
    STATE_BACKEND,
    LOCAL_STATE_PATH,
    STATE_S3_BUCKET,
    STATE_S3_KEY,
    AWS_REGION,
)

logger = logging.getLogger(__name__)


# ── Data model ────────────────────────────────────────────────────────────────

class TerraformResource:
    """
    Represents one resource as Terraform knows it.

    Attributes:
        resource_key  : "aws_instance.web" — type.name
        resource_type : "aws_instance"
        resource_name : "web"
        resource_id   : the AWS resource ID (e.g. "i-042e826eedb4ef34d")
        attributes    : full dict of all attributes from the state file
    """

    def __init__(
        self,
        resource_key: str,
        resource_type: str,
        resource_name: str,
        resource_id: str,
        attributes: dict,
    ):
        self.resource_key  = resource_key
        self.resource_type = resource_type
        self.resource_name = resource_name
        self.resource_id   = resource_id
        self.attributes    = attributes

    def get(self, attr: str, default=None):
        """Convenience method to read an attribute with a fallback."""
        return self.attributes.get(attr, default)

    def __repr__(self):
        return f"TerraformResource({self.resource_key}, id={self.resource_id})"


# ── State loading ─────────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    Load the raw Terraform state JSON from either local disk or S3.

    Returns the parsed JSON dict — the full tfstate structure.
    Raises FileNotFoundError / ValueError if the state cannot be loaded.
    """
    if STATE_BACKEND == "local":
        return _load_local_state()
    elif STATE_BACKEND == "remote":
        return _load_s3_state()
    else:
        raise ValueError(f"Unknown STATE_BACKEND: {STATE_BACKEND}. Use 'local' or 'remote'.")


def _load_local_state() -> dict:
    """
    Read terraform.tfstate from the local filesystem.

    During development you run 'terraform apply' locally, which writes
    the state file to terraform/terraform.tfstate. This function reads it.
    """
    state_path = Path(LOCAL_STATE_PATH)

    if not state_path.exists():
        raise FileNotFoundError(
            f"Terraform state file not found at {state_path}. "
            f"Run 'terraform apply' first to create your infrastructure."
        )

    logger.info(f"Loading local state from {state_path}")

    with open(state_path, "r") as f:
        raw = json.load(f)

    logger.info(f"State file loaded — terraform version: {raw.get('terraform_version', 'unknown')}")
    return raw


def _load_s3_state() -> dict:
    """
    Download terraform.tfstate from S3 remote backend.

    Used in GitHub Actions where there is no local state file.
    The bucket and key come from config.py / environment variables.
    """
    if not STATE_S3_BUCKET:
        raise ValueError(
            "STATE_S3_BUCKET is not set. "
            "Set it in config.py or as an environment variable."
        )

    logger.info(f"Loading remote state from s3://{STATE_S3_BUCKET}/{STATE_S3_KEY}")

    s3 = boto3.client("s3", region_name=AWS_REGION)

    try:
        response = s3.get_object(Bucket=STATE_S3_BUCKET, Key=STATE_S3_KEY)
        raw = json.loads(response["Body"].read().decode("utf-8"))
        logger.info("Remote state loaded from S3 successfully")
        return raw

    except s3.exceptions.NoSuchKey:
        raise FileNotFoundError(
            f"State file not found at s3://{STATE_S3_BUCKET}/{STATE_S3_KEY}. "
            f"Has terraform apply been run?"
        )


# ── State parsing ─────────────────────────────────────────────────────────────

def parse_state(raw_state: dict) -> dict[str, TerraformResource]:
    """
    Parse the raw tfstate JSON into a flat dict of TerraformResource objects.

    Terraform state structure (simplified):
    {
      "version": 4,
      "resources": [
        {
          "type": "aws_instance",
          "name": "web",
          "instances": [
            {
              "attributes": {
                "id": "i-042e826eedb4ef34d",
                "instance_type": "t3.micro",
                ...
              }
            }
          ]
        }
      ]
    }

    We flatten this into:
    {
      "aws_instance.web": TerraformResource(...)
    }

    Why flatten? The differ needs to look up resources by key quickly.
    A flat dict with "type.name" keys makes that O(1).
    """
    resources = {}

    # The top-level "resources" array contains all managed resources
    for resource in raw_state.get("resources", []):
        resource_type = resource.get("type", "")
        resource_name = resource.get("name", "")

        # Skip data sources — they're read-only and not managed by Terraform
        # mode = "data" for data sources, "managed" for real resources
        if resource.get("mode") == "data":
            continue

        # Skip resource types we don't scan
        if not _is_scannable(resource_type):
            continue

        # Each resource can have multiple instances (e.g. count = 3)
        # For our project, each resource has exactly one instance
        for i, instance in enumerate(resource.get("instances", [])):
            attrs = instance.get("attributes", {})
            resource_id = attrs.get("id", "")

            # For resources with count > 1, append index to the name
            suffix = f"[{i}]" if len(resource.get("instances", [])) > 1 else ""
            key = f"{resource_type}.{resource_name}{suffix}"

            resources[key] = TerraformResource(
                resource_key  = key,
                resource_type = resource_type,
                resource_name = resource_name,
                resource_id   = resource_id,
                attributes    = attrs,
            )

            logger.debug(f"Parsed resource: {key} (id={resource_id})")

    logger.info(f"Parsed {len(resources)} managed resources from state")
    return resources


def _is_scannable(resource_type: str) -> bool:
    """
    Return True if this resource type is one the drift detector scans.

    We only scan the resource types we have scanner logic for.
    Unknown resource types are skipped to avoid false positives.
    """
    scannable_types = {
        "aws_instance",
        "aws_security_group",
        "aws_s3_bucket",
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_versioning",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_vpc",
        "aws_subnet",
        "aws_internet_gateway",
        "aws_route_table",
    }
    return resource_type in scannable_types


# ── Convenience function ──────────────────────────────────────────────────────

def get_terraform_resources() -> dict[str, TerraformResource]:
    """
    Load and parse the Terraform state in one call.

    This is the main entry point used by aws_scanner.py and differ.py.

    Returns a dict of resource_key -> TerraformResource.
    """
    raw = load_state()
    return parse_state(raw)


def get_resource_ids_by_type(
    resources: dict[str, TerraformResource],
    resource_type: str
) -> list[str]:
    """
    Extract all AWS resource IDs for a given resource type.

    Example:
        ids = get_resource_ids_by_type(resources, "aws_instance")
        # returns ["i-042e826eedb4ef34d"]

    Used by aws_scanner.py to know which specific resources to query in AWS.
    """
    return [
        r.resource_id
        for r in resources.values()
        if r.resource_type == resource_type and r.resource_id
    ]
