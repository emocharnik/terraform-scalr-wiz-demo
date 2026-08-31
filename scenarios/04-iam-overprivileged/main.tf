# Scenario 04 — Over-privileged IAM
#
# Expected Wiz verdict: FAILED_BY_POLICY (Critical)
# Expected Scalr run:   plan succeeds -> Wiz post-plan step fails -> apply blocked
#
# The identity scenario, and the best one for showing why plan review by a human
# does not scale: the wildcards below read as unremarkable JSON at a glance.
#
# Findings planted below:
#   * Customer-managed policy granting Action "*" on Resource "*"
#   * Role assumable by any AWS principal ("AWS": "*")
#   * AdministratorAccess attached directly to a role
#   * Long-lived IAM user access key
#   * iam:PassRole with a wildcard resource (privilege-escalation path)
#   * KMS key policy open to the whole account with no condition

locals {
  tags = {
    Project  = "wiz-scalr-demo"
    Scenario = "04-iam-overprivileged"
  }
}

# FINDING: god-mode policy.
resource "aws_iam_policy" "god_mode" {
  name        = "${var.name_prefix}-god-mode"
  description = "Broad access for the platform automation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEverything"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })

  tags = local.tags
}

# FINDING: trust policy allows assumption by any AWS account on earth.
resource "aws_iam_role" "cross_account" {
  name = "${var.name_prefix}-cross-account"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { AWS = "*" }
      },
    ]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "cross_account_god_mode" {
  role       = aws_iam_role.cross_account.name
  policy_arn = aws_iam_policy.god_mode.arn
}

# FINDING: AWS-managed AdministratorAccess attached directly.
resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  role       = aws_iam_role.cross_account.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# FINDING: privilege escalation via unrestricted iam:PassRole.
resource "aws_iam_role" "ci_runner" {
  name = "${var.name_prefix}-ci-runner"

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

resource "aws_iam_role_policy" "ci_runner_passrole" {
  name = "${var.name_prefix}-ci-passrole"
  role = aws_iam_role.ci_runner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole", "iam:CreatePolicyVersion", "sts:AssumeRole"]
        Resource = "*"
      },
    ]
  })
}

# FINDING: long-lived static credentials.
resource "aws_iam_user" "service" {
  name = "${var.name_prefix}-service-account"
  tags = local.tags
}

resource "aws_iam_access_key" "service" {
  user = aws_iam_user.service.name
}

resource "aws_iam_user_policy_attachment" "service_god_mode" {
  user       = aws_iam_user.service.name
  policy_arn = aws_iam_policy.god_mode.arn
}

# FINDING: key policy with no principal restriction.
resource "aws_kms_key" "shared" {
  description         = "Shared demo key"
  enable_key_rotation = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAll"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "kms:*"
        Resource  = "*"
      },
    ]
  })

  tags = local.tags
}
