# Scenario 07 — Maximum severity
#
# Purpose: clear a Wiz IaC policy whose `severityThreshold` is CRITICAL.
#
# Scenarios 02 and 04 produced 101 findings between them and not one was rated
# Critical — wide-open security groups and wildcard IAM admin both land at High
# or below in Wiz's rule catalogue. This scenario reaches for the categories
# that are rated Critical: anonymous WRITE access to data, resources shared
# publicly with the entire internet, and public resource policies on secrets.
#
# Why this matters even while your Wiz policy is set to AUDIT:
#   Findings at or above the threshold survive filtering, so they appear in
#   run_tasks.wiz.result.iac.scanStatistics.criticalMatches. AUDIT means Wiz
#   won't fail the scan, but `wiz_severity_budget` reads that counter and blocks
#   the run anyway. Wiz reports, Scalr enforces.
#
# NO GUARANTEE OF SEVERITY. Wiz owns the rule catalogue and I cannot see it.
# Verify empirically -- see the verification loop in the README. If
# criticalMatches is still 0, the fix is the Wiz threshold, not more Terraform.

locals {
  tags = {
    Project  = "wiz-scalr-demo"
    Scenario = "07-critical-exposure"
  }
}

# ---------------------------------------------------------------------------
# Anonymous WRITE to data — worse than public read: anyone can overwrite
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "world_writable" {
  bucket        = "${var.name_prefix}-world-writable-e81b04"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "world_writable" {
  bucket                  = aws_s3_bucket.world_writable.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "world_writable" {
  bucket = aws_s3_bucket.world_writable.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "world_writable" {
  depends_on = [
    aws_s3_bucket_ownership_controls.world_writable,
    aws_s3_bucket_public_access_block.world_writable,
  ]

  bucket = aws_s3_bucket.world_writable.id
  acl    = "public-read-write"
}

# Anonymous full control over the bucket and everything in it.
resource "aws_s3_bucket_policy" "world_writable" {
  depends_on = [aws_s3_bucket_public_access_block.world_writable]

  bucket = aws_s3_bucket.world_writable.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AnonymousFullControl"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.world_writable.arn,
          "${aws_s3_bucket.world_writable.arn}/*",
        ]
      },
    ]
  })
}

# ---------------------------------------------------------------------------
# Shared with every AWS account on earth
# ---------------------------------------------------------------------------

resource "aws_ebs_volume" "sensitive" {
  availability_zone = "${var.region}a"
  size              = 20
  encrypted         = false
  tags              = local.tags
}

resource "aws_ebs_snapshot" "sensitive" {
  volume_id = aws_ebs_volume.sensitive.id
  tags      = local.tags
}

# Unencrypted snapshot shared outside the organisation. The AWS provider has no
# way to express `group = "all"` here, so full public sharing cannot be planted
# from Terraform -- this is the strongest form available.
resource "aws_snapshot_create_volume_permission" "external" {
  snapshot_id = aws_ebs_snapshot.sensitive.id
  account_id  = "123456789012"
}

# Public AMI.
resource "aws_ami_launch_permission" "public" {
  image_id = "ami-0c7217cdde317cfec"
  group    = "all"
}

# ---------------------------------------------------------------------------
# Public resource policies on secrets and code
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "${var.name_prefix}-prod-api-keys"
  recovery_window_in_days = 0
  tags                    = local.tags
}

# The entire internet can read production secrets.
resource "aws_secretsmanager_secret_policy" "api_keys" {
  secret_arn = aws_secretsmanager_secret.api_keys.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicSecretAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource  = "*"
      },
    ]
  })
}

resource "aws_ecr_repository" "app" {
  name                 = "${var.name_prefix}-critical-app"
  image_tag_mutability = "MUTABLE"
  tags                 = local.tags
}

resource "aws_ecr_repository_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicPushPull"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["ecr:*"]
      },
    ]
  })
}

resource "aws_sqs_queue" "jobs" {
  name = "${var.name_prefix}-critical-jobs"
  tags = local.tags
}

resource "aws_sqs_queue_policy" "jobs" {
  queue_url = aws_sqs_queue.jobs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicQueueAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.jobs.arn
      },
    ]
  })
}
