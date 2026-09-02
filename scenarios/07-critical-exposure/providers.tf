terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Demo-safe by design.
#
# These credentials are fake and every AWS API pre-flight check is skipped, so
# `terraform plan` produces a complete plan without ever contacting AWS. That is
# all the Wiz integration needs: Scalr exports the plan JSON and Wiz scans it
# post-plan. Nothing here can be applied against a real account.
#
# To point a scenario at a real AWS account instead, delete this provider block
# and attach a Scalr provider configuration to the workspace.
provider "aws" {
  region = var.region

  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

variable "region" {
  description = "AWS region used for the demo plan."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name so parallel demos do not collide."
  type        = string
  default     = "wiz-demo"
}
