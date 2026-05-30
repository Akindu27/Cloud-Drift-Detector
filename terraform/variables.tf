# ─────────────────────────────────────────────────────────────────────────────
# variables.tf
#
# Input variables for the Terraform configuration.
# Override defaults by creating a terraform.tfvars file:
#
#   aws_region    = "ap-southeast-1"
#   environment   = "dev"
#   instance_type = "t2.micro"
#
# Or pass on the command line:
#   terraform apply -var="environment=prod"
# ─────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region to deploy resources in"
  type        = string
  default     = "ap-southeast-1"
}

variable "environment" {
  description = "Environment name — used in tags and resource names"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name — used as prefix for all resource names"
  type        = string
  default     = "drift-detector"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type — t2.micro is free tier eligible"
  type        = string
  default     = "t3.micro"
}
