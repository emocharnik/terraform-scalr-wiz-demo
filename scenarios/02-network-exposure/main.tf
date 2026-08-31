# Scenario 02 — Network exposure
#
# Expected Wiz verdict: FAILED_BY_POLICY (Critical / High)
# Expected Scalr run:   plan succeeds -> Wiz post-plan step fails -> apply blocked
#
# Use this one when the audience is a network or infra team. The security group
# below is the single most common real-world finding in any cloud estate.
#
# Findings planted below:
#   * SSH (22) open to 0.0.0.0/0
#   * RDP (3389) open to 0.0.0.0/0
#   * MySQL (3306) open to 0.0.0.0/0
#   * All ports / all protocols open to ::/0
#   * RDS instance marked publicly_accessible
#   * Load balancer listener serving plaintext HTTP
#   * VPC with no flow logs

locals {
  tags = {
    Project  = "wiz-scalr-demo"
    Scenario = "02-network-exposure"
  }
}

# FINDING: no flow logs attached to this VPC.
resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${var.name_prefix}-public-a" })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${var.name_prefix}-public-b" })
}

# FINDING: the classic "temporarily open it up for debugging" security group.
resource "aws_security_group" "wide_open" {
  name        = "${var.name_prefix}-wide-open"
  description = "Temporary troubleshooting access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL from anywhere"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "Everything, over IPv6"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# FINDING: an internet-reachable database.
resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags       = local.tags
}

resource "aws_db_instance" "orders" {
  identifier     = "${var.name_prefix}-orders"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  db_name           = "orders"
  username          = "admin"

  # FINDING: hardcoded credential in version control.
  password = "SuperSecret123!"

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.wide_open.id]

  publicly_accessible = true
  skip_final_snapshot = true

  tags = local.tags
}

# FINDING: plaintext HTTP listener, no redirect to TLS.
resource "aws_lb" "public" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.wide_open.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  drop_invalid_header_fields = false
  enable_deletion_protection = false

  tags = local.tags
}

resource "aws_lb_target_group" "app" {
  name     = "${var.name_prefix}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  tags     = local.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
