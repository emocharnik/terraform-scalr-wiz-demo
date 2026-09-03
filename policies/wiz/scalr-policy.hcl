version = "v1"

# Baseline: any Wiz failure, or any scan that did not complete, stops the run.
# This alone reproduces auto-fail mode. Start the demo with only this enabled.
policy "wiz_verdict" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

# Blocks when a Wiz policy matched the plan, naming which one -- and does so
# whether Wiz set that policy to AUDIT or BLOCK. On an audit-mode tenant this is
# what actually gates the deploy, since Wiz itself returns only a warning.
#
# Soft-mandatory, so an approver can override on the run. That gives you the
# approval flow to demo alongside the block.
policy "wiz_failed_policies" {
  enabled           = true
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
