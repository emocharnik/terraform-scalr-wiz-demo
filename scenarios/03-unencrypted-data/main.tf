# Scenario 03 — Unencrypted data at rest
#
# Expected Wiz verdict: FAILED_BY_POLICY (High / Medium)
# Expected Scalr run:   plan succeeds -> Wiz post-plan step fails -> apply blocked
#
# The compliance scenario. Everything here maps directly to a SOC 2 / PCI / HIPAA
# control, which makes it the right one to show a GRC or audit audience.
#
# Findings planted below:
#   * EBS volume with encryption disabled
#   * RDS instance unencrypted, zero-day backup retention, no deletion protection
#   * DynamoDB table with no server-side encryption block
#   * SQS queue with no KMS key
#   * EFS file system unencrypted
#   * SNS topic unencrypted
#   * CloudWatch log group with no KMS key and no retention

locals {
  tags = {
    Project  = "wiz-scalr-demo"
    Scenario = "03-unencrypted-data"
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.43.0.0/16"
  tags       = merge(local.tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_subnet" "a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.43.1.0/24"
  availability_zone = "${var.region}a"
  tags              = local.tags
}

resource "aws_subnet" "b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.43.2.0/24"
  availability_zone = "${var.region}b"
  tags              = local.tags
}

# FINDING: unencrypted block storage.
resource "aws_ebs_volume" "data" {
  availability_zone = "${var.region}a"
  size              = 100
  type              = "gp3"
  encrypted         = false
  tags              = merge(local.tags, { Name = "${var.name_prefix}-data" })
}

# FINDING: unencrypted RDS, no backups, no deletion protection, single AZ.
resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
  tags       = local.tags
}

resource "aws_db_instance" "billing" {
  identifier     = "${var.name_prefix}-billing"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  db_name           = "billing"
  username          = "billing_admin"
  password          = "ChangeMe123!"

  db_subnet_group_name = aws_db_subnet_group.main.name

  storage_encrypted       = false
  backup_retention_period = 0
  deletion_protection     = false
  multi_az                = false
  skip_final_snapshot     = true

  tags = local.tags
}

# FINDING: no server_side_encryption block, no point-in-time recovery.
resource "aws_dynamodb_table" "sessions" {
  name         = "${var.name_prefix}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }

  tags = local.tags
}

# FINDING: queue contents unencrypted at rest.
resource "aws_sqs_queue" "events" {
  name = "${var.name_prefix}-events"
  tags = local.tags
}

# FINDING: unencrypted shared file system.
resource "aws_efs_file_system" "shared" {
  creation_token = "${var.name_prefix}-shared"
  encrypted      = false
  tags           = local.tags
}

# FINDING: unencrypted topic.
resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
  tags = local.tags
}

# FINDING: logs retained forever, unencrypted.
resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.name_prefix}/app"
  retention_in_days = 0
  tags              = local.tags
}
