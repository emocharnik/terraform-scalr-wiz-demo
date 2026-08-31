# Scenario 01 — Publicly exposed storage
#
# Expected Wiz verdict: FAILED_BY_POLICY (Critical / High)
# Expected Scalr run:   plan succeeds -> Wiz post-plan step fails -> apply blocked
#
# This is the headline scenario. Every finding here is one an auditor recognises
# on sight, and none of it is visible from `terraform plan` output alone --
# the plan is perfectly valid Terraform. That gap is the whole pitch.
#
# Findings planted below:
#   * S3 bucket readable by the entire internet via bucket policy Principal "*"
#   * Public access block explicitly disabled on all four controls
#   * No server-side encryption configuration
#   * No versioning (no recovery from ransomware / accidental delete)
#   * No access logging
#   * Public ACL granting READ to AllUsers

locals {
  tags = {
    Project  = "wiz-scalr-demo"
    Scenario = "01-public-storage"
  }
}

resource "aws_s3_bucket" "customer_exports" {
  bucket        = "${var.name_prefix}-customer-exports-3b71de"
  force_destroy = true
  tags          = local.tags
}

# FINDING: all four public-access guardrails turned off.
resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# FINDING: public-read ACL.
resource "aws_s3_bucket_acl" "customer_exports" {
  depends_on = [
    aws_s3_bucket_ownership_controls.customer_exports,
    aws_s3_bucket_public_access_block.customer_exports,
  ]

  bucket = aws_s3_bucket.customer_exports.id
  acl    = "public-read"
}

# FINDING: anonymous principal can read every object in the bucket.
resource "aws_s3_bucket_policy" "customer_exports" {
  depends_on = [aws_s3_bucket_public_access_block.customer_exports]

  bucket = aws_s3_bucket.customer_exports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadForAnyone"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.customer_exports.arn,
          "${aws_s3_bucket.customer_exports.arn}/*",
        ]
      },
    ]
  })
}

# FINDING: no encryption, no versioning, no logging on a second bucket that
# holds database snapshots -- deliberately the most sensitive data in the demo.
resource "aws_s3_bucket" "db_snapshots" {
  bucket        = "${var.name_prefix}-db-snapshots-3b71de"
  force_destroy = true
  tags          = local.tags
}

# FINDING: ECR repository allows mutable tags and skips image scanning.
resource "aws_ecr_repository" "app" {
  name                 = "${var.name_prefix}-app"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  tags = local.tags
}
