# ─────────────────────────────────────────────────────────────────────────────
# main.tf
#
# Defines the AWS infrastructure that the drift detector watches.
# This is intentionally simple — a VPC, one EC2 instance, one S3 bucket,
# and a security group. Just enough to demonstrate every drift type.
#
# After 'terraform apply', the drift detector compares this definition
# against what actually exists in AWS. Any manual change you make in the
# AWS console will show up as drift on the next scan.
#
# To apply:
#   cd terraform/
#   terraform init
#   terraform apply
#
# To destroy (avoid charges):
#   terraform destroy
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # ── Remote state backend ───────────────────────────────────────────────────
  # Stores the state file in S3 instead of locally.
  # This means GitHub Actions can read the same state when running scans.
  #
  # Before running terraform init, create the S3 bucket and DynamoDB table:
  #   aws s3 mb s3://YOUR-BUCKET-NAME --region ap-southeast-1
  #   aws dynamodb create-table \
  #     --table-name terraform-locks \
  #     --attribute-definitions AttributeName=LockID,AttributeType=S \
  #     --key-schema AttributeName=LockID,KeyType=HASH \
  #     --billing-mode PAY_PER_REQUEST \
  #     --region ap-southeast-1
  #
  # Then uncomment this block and replace YOUR-BUCKET-NAME:
  #
  # backend "s3" {
  #   bucket         = "YOUR-BUCKET-NAME-terraform-state"
  #   key            = "drift-detector/terraform.tfstate"
  #   region         = "ap-southeast-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  # These tags are applied to EVERY resource Terraform creates.
  # The drift detector flags any resource missing "ManagedBy = terraform"
  # as tag drift — so this default tag is important.
  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Environment = var.environment
      Project     = "cloud-drift-detector"
    }
  }
}

# ── Data sources ───────────────────────────────────────────────────────────────
# Fetch the latest Amazon Linux 2023 AMI automatically.
# This avoids hardcoding an AMI ID that becomes stale over time.
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# Fetch current AWS account ID and region dynamically.
# Used in outputs and resource naming.
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── VPC ────────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Public subnet — the EC2 instance lives here
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
    Tier = "public"
  }
}

# Internet gateway — allows the subnet to reach the internet
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Route table — sends all traffic through the internet gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ── Security group ─────────────────────────────────────────────────────────────
# This is the resource the drift detector watches most closely.
# The rule below only allows HTTPS (443) inbound — no SSH.
# If someone adds a port 22 rule manually in the AWS console,
# the drift detector will flag it as CRITICAL security drift.
resource "aws_security_group" "web" {
  name        = "${var.project_name}-web-sg"
  description = "Security group for web server - managed by Terraform"
  vpc_id      = aws_vpc.main.id

  # Allow HTTPS inbound from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  # Allow HTTP inbound (redirect to HTTPS in practice)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-web-sg"
  }
}

# ── EC2 instance ───────────────────────────────────────────────────────────────
# A t2.micro instance (free tier eligible).
# The drift detector will flag it if someone changes the instance type
# manually in the console.
resource "aws_instance" "web" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]

  # No key pair — use SSM Session Manager for access instead of SSH.
  # This is the production-standard approach: no open port 22 needed.

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "${var.project_name}-web-server"
    Role = "web"
  }
}

# ── S3 bucket ──────────────────────────────────────────────────────────────────
# The drift detector checks this bucket for:
#   - Public access (CRITICAL if enabled)
#   - Versioning disabled (WARNING)
#   - Encryption disabled (WARNING)
resource "aws_s3_bucket" "app" {
  # Bucket names must be globally unique — using account ID as suffix
  bucket = "${var.project_name}-app-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "${var.project_name}-app-bucket"
    Purpose = "application-storage"
  }
}

# Block all public access — this is the correct default
resource "aws_s3_bucket_public_access_block" "app" {
  bucket = aws_s3_bucket.app.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning
resource "aws_s3_bucket_versioning" "app" {
  bucket = aws_s3_bucket.app.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "app" {
  bucket = aws_s3_bucket.app.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
