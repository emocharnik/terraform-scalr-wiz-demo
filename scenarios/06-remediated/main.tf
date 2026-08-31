# Scenario 06 — Remediated
#
# Expected Wiz verdict: PASSED
# Expected Scalr run:   plan -> Wiz post-plan step green -> apply available
#
# The payoff scenario. This is scenarios 01 through 04 rebuilt correctly:
# same workloads, same shapes, every finding closed. Run it straight after a
# blocked run so the audience sees the pipeline go from red to green on a code
# change alone -- no ticket, no exception, no security review meeting.
#
# Suggested demo move: open this file side by side with 01/02/04 and diff them.

locals {
  tags = {
    Project     = "wiz-scalr-demo"
    Scenario    = "06-remediated"
    Owner       = "platform-team"
    Environment = "demo"
    DataClass   = "confidential"
  }
}

# ---------------------------------------------------------------------------
# Keys — rotation on, scoped key policy
# ---------------------------------------------------------------------------

resource "aws_kms_key" "data" {
  description             = "CMK for demo data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

# ---------------------------------------------------------------------------
# Storage — private, encrypted, versioned, logged  (fixes scenario 01)
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-remediated-logs-c40e82"
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

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "customer_exports" {
  bucket = "${var.name_prefix}-customer-exports-c40e82"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "customer_exports" {
  bucket        = aws_s3_bucket.customer_exports.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "customer-exports/"
}

resource "aws_s3_bucket_lifecycle_configuration" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  rule {
    id     = "expire-old-exports"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# TLS enforced in transit, on top of encryption at rest.
resource "aws_s3_bucket_policy" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.customer_exports.arn,
          "${aws_s3_bucket.customer_exports.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

resource "aws_ecr_repository" "app" {
  name                 = "${var.name_prefix}-app-remediated"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Network — private subnets, scoped ingress, TLS, flow logs  (fixes scenario 02)
# ---------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.46.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${var.name_prefix}/vpc-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.data.arn
  tags              = local.tags
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.name_prefix}-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      },
    ]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.name_prefix}-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      },
    ]
  })
}

resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_logs.arn
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  log_destination_type = "cloud-watch-logs"
  tags                 = local.tags
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.46.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name_prefix}-private-a" })
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.46.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "${var.name_prefix}-private-b" })
}

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-remediated"
  description = "Public TLS ingress to the application load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To the application tier"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  tags = local.tags
}

resource "aws_security_group" "database" {
  name        = "${var.name_prefix}-db-remediated"
  description = "PostgreSQL reachable only from the application tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from the ALB tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  tags = local.tags
}

resource "aws_lb" "app" {
  name               = "${var.name_prefix}-alb-remediated"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb"
    enabled = true
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Data — encrypted, backed up, protected  (fixes scenario 03)
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnets-remediated"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = local.tags
}

resource "aws_db_instance" "billing" {
  identifier     = "${var.name_prefix}-billing-remediated"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  db_name           = "billing"
  username          = "billing_admin"

  # Credentials are generated and rotated by AWS, never written to source.
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]

  publicly_accessible = false

  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.data.arn
  backup_retention_period         = 30
  deletion_protection             = true
  multi_az                        = true
  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = local.tags
}

resource "aws_dynamodb_table" "sessions" {
  name         = "${var.name_prefix}-sessions-remediated"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = local.tags
}

resource "aws_sqs_queue" "events" {
  name                              = "${var.name_prefix}-events-remediated"
  kms_master_key_id                 = aws_kms_key.data.arn
  kms_data_key_reuse_period_seconds = 300
  tags                              = local.tags
}

# ---------------------------------------------------------------------------
# Identity — scoped, conditioned, no static keys  (fixes scenario 04)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "app" {
  name = "${var.name_prefix}-app-remediated"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "ec2.amazonaws.com" }
      },
    ]
  })

  tags = local.tags
}

# Least privilege: two actions, one bucket prefix, one key.
resource "aws_iam_role_policy" "app" {
  name = "${var.name_prefix}-app-remediated"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadWriteOwnPrefix"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.customer_exports.arn}/app/*"
      },
      {
        Sid      = "UseDataKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.data.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com"
          }
        }
      },
    ]
  })
}
