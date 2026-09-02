# Publicly reachable data services with authentication effectively removed.
# These are the categories most likely to carry a Critical rating: a datastore
# on the public internet holding real data, with no encryption and no network
# boundary in front of it.

resource "aws_vpc" "main" {
  cidr_block           = "10.47.0.0/16"
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.name_prefix}-critical-vpc" })
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.47.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags                    = local.tags
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.47.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true
  tags                    = local.tags
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = local.tags
}

# Every port, every protocol, from anywhere — on both IPv4 and IPv6.
resource "aws_security_group" "everything" {
  name        = "${var.name_prefix}-everything-open"
  description = "No restrictions"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 65535
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = local.tags
}

# Data warehouse on the public internet, unencrypted, hardcoded credentials.
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "${var.name_prefix}-analytics"
  database_name      = "analytics"
  master_username    = "admin"
  master_password    = "Password123!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"

  publicly_accessible                 = true
  encrypted                           = false
  skip_final_snapshot                 = true
  automated_snapshot_retention_period = 0

  vpc_security_group_ids = [aws_security_group.everything.id]

  tags = local.tags
}

# Search cluster with an anonymous access policy and no encryption anywhere.
resource "aws_opensearch_domain" "logs" {
  domain_name = "${var.name_prefix}-logs"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = false
  }

  node_to_node_encryption {
    enabled = false
  }

  domain_endpoint_options {
    enforce_https = false
  }

  # Anonymous read/write to the entire domain.
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "es:*"
        Resource  = "*"
      },
    ]
  })

  tags = local.tags
}

# Kubernetes API server reachable from the whole internet.
resource "aws_iam_role" "eks" {
  name = "${var.name_prefix}-eks-cluster"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "eks.amazonaws.com" }
      },
    ]
  })

  tags = local.tags
}

resource "aws_eks_cluster" "main" {
  name     = "${var.name_prefix}-critical"
  role_arn = aws_iam_role.eks.arn

  vpc_config {
    subnet_ids              = [aws_subnet.public_a.id, aws_subnet.public_b.id]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
    security_group_ids      = [aws_security_group.everything.id]
  }

  tags = local.tags
}

# Password policy that permits trivially guessable console credentials.
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_uppercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
}
