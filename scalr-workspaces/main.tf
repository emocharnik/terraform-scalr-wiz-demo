terraform {
  required_providers {
    scalr = {
      source = "scalr/scalr"
    }
  }
}

locals {
  scenarios = [
    "07-critical-exposure",
  ]

  repository_id = "emocharnik/terraform-scalr-wiz-demo"
}

data "scalr_environment" "aws" {
  name = "aws"
}

data "scalr_vcs_provider" "root" {
  name = "wiz-demo-github"
}

resource "scalr_workspace" "scenarios" {
  for_each = toset(local.scenarios)

  environment_id = data.scalr_environment.aws.id
  name           = each.value

  working_directory = "scenarios/${each.value}"

  vcs_provider_id = data.scalr_vcs_provider.root.id

  vcs_repo {
    identifier = local.repository_id
    branch = "main"
    trigger_prefixes = ["scenarios/${each.value}"]
  }
}

resource "scalr_policy_group" "wiz" {
  name            = "wiz"
  vcs_provider_id = data.scalr_vcs_provider.root.id
  vcs_repo {
    identifier = local.repository_id
    branch = "main"
    path = "policies/wiz"
  }

  environments = [data.scalr_environment.aws.id]
}
