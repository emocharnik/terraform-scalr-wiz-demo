version = "v1"

# Guard the guard: fails the run if the Wiz CI/CD scan policies evaluated on it
# cannot stop a bad plan -- IaC policy missing, severityThreshold too high, or
# enforcement set to AUDIT. Enable this FIRST. On a stock Wiz tenant it fires
# immediately, which is the point: without it the integration reports
# PASSED_BY_POLICY on infrastructure that is wide open.
policy "wiz_integration_hygiene" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

# Baseline: any Wiz failure, or any scan that did not complete, stops the run.
# This alone reproduces auto-fail mode. Start the demo with only this enabled.
policy "wiz_verdict" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

# Severity budget: Critical/High block, Medium/Low are tolerated up to a limit.
# Soft-mandatory so a violation can be overridden by an approver on the run,
# which gives you the approval flow to demo as well as the block.
#
# Leave this DISABLED for the first pass of the demo, then flip it to true and
# re-run scenario 05 to show the same Wiz result producing a different outcome.
policy "wiz_severity_budget" {
  enabled           = false
  enforcement_level = "soft-mandatory"
}

# Governed exceptions: a Wiz failure can be waived by tagging the workspace
# `wiz-break-glass`, except in production environments.
#
# Mutually exclusive with wiz_verdict in practice -- wiz_verdict blocks
# unconditionally, so enable one or the other, not both.
policy "wiz_break_glass" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}
