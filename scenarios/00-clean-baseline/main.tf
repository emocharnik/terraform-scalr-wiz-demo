# Scenario 00 — Clean baseline
#
# Expected Wiz verdict: PASSED
# Expected Scalr run:   plan -> Wiz post-plan step green -> apply available
#
# Purpose in the demo: establish that the Wiz step is real and is actually
# running, before you show it catching anything. Keep this one short so the
# audience sees a green pipeline in under a minute.

locals {
  tags = {
    Project     = "wiz-scalr-demo"
    Scenario    = "00-clean-baseline"
    Owner       = "platform-team"
    Environment = "demo"
    DataClass   = "internal"
  }
}

resource "aws_kms_key" "this" {
  description             = "CMK for the clean baseline bucket"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_s3_bucket" "this" {
  bucket = "${var.name_prefix}-baseline-9f2c1a"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.this.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/"
}

resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-baseline-logs-9f2c1a"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
