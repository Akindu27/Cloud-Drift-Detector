# Cloud Drift Detector

A Python-based cloud security posture tool that compares live AWS infrastructure against Terraform state and detects configuration drift — automatically scanning every 6 hours via GitHub Actions and generating colour-coded HTML reports.

---

## What is infrastructure drift?

Drift happens when someone manually changes an AWS resource outside of Terraform — opening a port in the console "temporarily", changing an instance type, disabling bucket encryption. Terraform doesn't know and won't fix it. This tool catches it.

```
Terraform state  →  what your infrastructure SHOULD look like
Live AWS account →  what it ACTUALLY looks like
Drift detector   →  finds the difference
```

---

## Architecture

```
Terraform state (tfstate)          Live AWS account (boto3)
        │                                    │
        ▼                                    ▼
  state_parser.py              aws_scanner.py
  (parse JSON)                 (EC2, SGs, S3, tags)
        │                                    │
        └──────────────┬─────────────────────┘
                       ▼
                  differ.py
              (compare + classify)
                       │
                       ▼
                 reporter.py
           (HTML report + JSON output)
                       │
              ┌────────┴────────┐
              ▼                 ▼
         reports/           Slack alert
      (local files)      (if webhook set)
```

GitHub Actions runs the full pipeline on a 6-hour cron schedule. Reports are uploaded as workflow artifacts downloadable from the Actions run page.

---

## Drift types detected

| Type | Severity | Example |
|---|---|---|
| Security | Critical | SSH (port 22) open to 0.0.0.0/0 |
| Security | Critical | S3 bucket public access enabled |
| Config | Warning | EC2 instance type changed manually |
| Config | Warning | S3 versioning or encryption disabled |
| Ghost | Critical | Resource exists in AWS but not in Terraform |
| Tag | Critical | Resource missing `ManagedBy: terraform` tag |
| Tag | Warning | Resource missing `Environment` or `Project` tag |

---

## Tech stack

- **Python 3.12** — scanner core
- **boto3** — AWS SDK (EC2, S3, IAM, STS API calls)
- **Terraform** — defines and provisions the watched infrastructure
- **Jinja2** — HTML report templating
- **GitHub Actions** — automated scheduling, report artifact upload
- **pytest + moto** — unit tests with mocked AWS API calls

---

## Project structure

```
cloud-drift-detector/
├── scanner/
│   ├── config.py        # all settings and thresholds
│   ├── state_parser.py  # reads Terraform state file
│   ├── aws_scanner.py   # queries live AWS via boto3
│   ├── differ.py        # compares state vs live, produces DriftItems
│   ├── reporter.py      # generates HTML + JSON reports
│   └── main.py          # orchestrates full scan pipeline
├── terraform/
│   ├── main.tf          # VPC, EC2, S3, security group definitions
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfstate
├── tests/
│   └── test_scanner.py
├── .github/
│   └── workflows/
│       └── drift-scan.yml
├── reports/             # generated reports (gitignored)
└── requirements.txt
```

---

## Running locally

```bash
git clone https://github.com/Akindu27/cloud-drift-detector.git
cd cloud-drift-detector
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure AWS credentials
aws configure

# Deploy infrastructure
cd terraform && terraform init && terraform apply && cd ..

# Run scan
python3 -m scanner.main
```

Reports are saved to `reports/` as `drift_report_TIMESTAMP.html` and `.json`.

---

## Simulating drift

```bash
# 1. Scan clean infrastructure — expect 0 findings
python3 -m scanner.main

# 2. Manually add SSH rule to security group in AWS console
#    EC2 → Security Groups → drift-detector-web-sg
#    Add inbound: SSH / TCP / 22 / 0.0.0.0/0

# 3. Scan again — expect 1 CRITICAL finding
python3 -m scanner.main

# 4. Remove the rule and scan again — back to 0 findings
```

---

## GitHub Actions setup

Set these secrets in your GitHub repo (Settings → Secrets → Actions):

```
AWS_ACCESS_KEY_ID       IAM user access key
AWS_SECRET_ACCESS_KEY   IAM user secret key  
SLACK_WEBHOOK_URL       Slack incoming webhook (optional)
```

The workflow runs every 6 hours, on push to main, and on manual trigger. When critical drift is found, the workflow exits with code 1 — visible as a failed run in the Actions tab. The HTML report is always uploaded as a downloadable artifact.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No drift, or only warnings |
| 1 | Critical drift found |

The exit code makes the scanner usable as a CI/CD gate — fail the pipeline if someone merges Terraform changes that introduce security drift.

---

## Note on state file

This project commits `terraform.tfstate` to the repository for simplicity. In production, state should be stored in S3 with DynamoDB locking:

```hcl
backend "s3" {
  bucket         = "your-terraform-state-bucket"
  key            = "drift-detector/terraform.tfstate"
  region         = "ap-southeast-1"
  encrypt        = true
  dynamodb_table = "terraform-locks"
}
```

The remote backend config is commented out in `terraform/main.tf` and ready to enable.

---

## What I learned

- How Terraform state works internally — JSON structure, resource modes, attribute storage
- How boto3 interacts with the AWS API — client vs resource, paginators, error handling
- Why S3 requires multiple separate API calls per bucket (public access block, versioning, encryption, tags are all separate endpoints)
- How to use `@dataclass` for clean data models
- How GitHub Actions cron scheduling works and how exit codes gate CI/CD pipelines
- The practical difference between config drift, security drift, ghost resources, and tag drift

---

*Built by [Akindu Gunarathna](https://github.com/Akindu27) — github.com/Akindu27/cloud-drift-detector*
