# Scenario 05 — Findings, but nothing critical
#
# Expected Wiz verdict: FAILED_BY_POLICY, but only Low / Medium findings
# Expected Scalr run:   depends entirely on which policy you enable --
#                         * auto-fail mode          -> run blocked
#                         * wiz_verdict policy      -> run blocked
#                         * wiz_severity_budget     -> run PASSES with a warning
#
# This is the scenario that justifies policy-check mode over auto-fail. Same
# Wiz result, two different business outcomes, decided by your own Rego rather
# than by a vendor's pass/fail bit. Run it twice in the demo -- once with
# wiz_severity_budget disabled, once with it enabled -- and let the audience
# watch the verdict change without the Terraform changing.
#
# NOTE: severity assignment belongs to your Wiz CI/CD scan policy, not to this
# repository. Run this scenario once against your own Wiz tenant and confirm it
# produces no Critical/High before you rely on it in front of an audience.
#
# Findings planted below (all minor by default Wiz rules):
#   * Resources missing the organisation's required tags
#   * S3 bucket with no lifecycle / expiration rule
#   * Load balancer with access logging disabled
#   * EC2 instance without detailed monitoring
#   * Security group rules with no description

resource "aws_s3_bucket" "reports" {
  bucket = "${var.name_prefix}-reports-77a410"

  # Deliberately missing Owner / DataClass tags.
  tags = {
    Project = "wiz-scalr-demo"
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

# No aws_s3_bucket_lifecycle_configuration -- objects are kept forever.

resource "aws_vpc" "main" {
  cidr_block = "10.45.0.0/16"
  tags       = { Project = "wiz-scalr-demo" }
}

resource "aws_subnet" "a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.45.1.0/24"
  availability_zone = "${var.region}a"
  tags              = { Project = "wiz-scalr-demo" }
}

# Correctly scoped to the VPC CIDR -- but the rules carry no description.
resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app"
  description = "Application tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "wiz-scalr-demo" }
}

# Encrypted root volume, no public IP -- but no detailed monitoring and IMDSv2
# is optional rather than required.
resource "aws_instance" "app" {
  ami                         = "ami-0c7217cdde317cfec" # Ubuntu 22.04, us-east-1
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.a.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  associate_public_ip_address = false
  monitoring                  = false

  root_block_device {
    encrypted   = true
    volume_size = 20
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  tags = { Project = "wiz-scalr-demo" }
}
