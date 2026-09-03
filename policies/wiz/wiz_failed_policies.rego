# Enforce on WHICH Wiz policies objected, with a per-policy allowance.
#
# This replaces an earlier severity-budget policy that could not work. Scalr's
# Wiz payload does not carry per-finding detail: verified against real captures,
# `result.iac.ruleMatches` is null and every counter in
# `result.iac.scanStatistics` reads 0 even on a scan whose policy failed. There
# are no severities to budget against. What the payload does carry is which
# policies matched, so that is what this policy enforces on.
#
# Enforcement: soft-mandatory (see scalr-policy.hcl) -- a violation stops the
# run but an approver can override it, which gives you an approval flow to demo
# on top of the block.
#
# Schema, verified:
#   run_tasks.wiz.result.iac.failedPolicyMatches[]
#     .policy.name          "Demo IaC policy"
#     .policy.type          "IAC"
#     .policy.builtin       bool
#     .ignoreReason         null, or why the match was ignored
#     .matchedIgnoreRules   null, or the ignore rules that fired
#
# Note this fires regardless of whether Wiz set the policy to AUDIT or BLOCK:
# a match is a match. That is the point -- it decouples your gate from how the
# Wiz administrator has configured enforcement for other pipelines.

package terraform

import rego.v1

wiz_fp_post_plan if {
	input.tfplan
}

wiz_fp_matches := object.get(
	input,
	["run_tasks", "wiz", "result", "iac", "failedPolicyMatches"],
	[],
)

# Policies allowed to match without stopping the run. Use this for a policy that
# is genuinely advisory in your organisation -- naming it here is a deliberate,
# reviewable decision, unlike silently tolerating every warning.
wiz_fp_advisory_policies := set()

# A match that Wiz itself ignored (an ignore rule fired) is not a violation.
wiz_fp_is_ignored(match) if {
	object.get(match, "ignoreReason", null) != null
}

wiz_fp_is_ignored(match) if {
	rules := object.get(match, "matchedIgnoreRules", null)
	is_array(rules)
	count(rules) > 0
}

wiz_fp_enforced contains match if {
	some match in wiz_fp_matches
	not wiz_fp_is_ignored(match)
	not object.get(match, ["policy", "name"], "") in wiz_fp_advisory_policies
}

wiz_failed_policies_violations contains reason if {
	wiz_fp_post_plan

	some match in wiz_fp_enforced
	name := object.get(match, ["policy", "name"], "<unnamed policy>")
	ptype := object.get(match, ["policy", "type"], "UNKNOWN")

	reason := sprintf(
		"Wiz: policy '%s' (%s) matched this plan. Open the Wiz step for the findings it objected to. This blocks regardless of whether Wiz is set to AUDIT or BLOCK.",
		[name, ptype],
	)
}

deny contains reason if {
	some reason in wiz_failed_policies_violations
}
