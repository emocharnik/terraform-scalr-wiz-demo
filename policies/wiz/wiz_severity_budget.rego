# Severity-aware Wiz enforcement — block on Critical/High, tolerate the rest.
#
# This is the policy that justifies choosing "Policy check" mode over
# "Auto-fail". Auto-fail gives you one bit: Wiz passed or it didn't. Here the
# same Wiz result is graded against a budget you own, so a plan carrying three
# Low findings ships while a plan carrying one Critical does not.
#
# Enforcement: soft-mandatory (see scalr-policy.hcl) -- a violation stops the
# run but an approver with the right permission can override it, which gives you
# an approval flow to demo on top of the block itself.
#
# ---------------------------------------------------------------------------
# ON THE NESTED SCHEMA — READ BEFORE DEMOING
# ---------------------------------------------------------------------------
# Scalr documents `status.verdict` as stable but explicitly notes that Wiz owns
# the nested result schema. Rather than hard-code a path that may shift, this
# policy walks the whole Wiz result and collects any object carrying a
# `severity` string, skipping objects that also carry a passing status.
#
# That is deliberately tolerant, and it means counts are approximate: a result
# that repeats severity at both the rule and the match level can double-count.
# Before you rely on the exact numbers in front of an audience:
#   1. Run any failing scenario with this policy group linked.
#   2. Open the run's policy check step and copy the real policy input.
#   3. Paste it into wiz_severity_budget_mock.json, replacing the placeholder.
#   4. Tighten the walk below into a direct path, and re-run `opa test`.

package terraform

import rego.v1

wiz_sev_post_plan if {
	input.tfplan
}

wiz_sev_result := object.get(input, ["run_tasks", "wiz"], {})

# How many findings of each severity this account is willing to ship.
# Tune these to make a scenario pass or fail on demand during the demo.
wiz_sev_budget := {
	"CRITICAL": 0,
	"HIGH": 0,
	"MEDIUM": 5,
	"LOW": 20,
}

wiz_sev_passing_status := {"PASSED", "PASS", "PASSING", "SUCCESS", "SKIPPED", "NOT_APPLICABLE", "IGNORED"}

# An object counts as "resolved" if any of its status-ish fields reads as a pass.
wiz_sev_is_passing(obj) if {
	some key in ["status", "result", "state", "outcome"]
	value := object.get(obj, key, null)
	is_string(value)
	upper(value) in wiz_sev_passing_status
}

wiz_sev_findings contains obj if {
	walk(wiz_sev_result, [_, obj])
	is_object(obj)
	is_string(obj.severity)
	not wiz_sev_is_passing(obj)
}

wiz_sev_count(level) := count([obj |
	some obj in wiz_sev_findings
	upper(obj.severity) == level
])

wiz_severity_budget_violations contains reason if {
	wiz_sev_post_plan

	some level, allowed in wiz_sev_budget
	found := wiz_sev_count(level)
	found > allowed

	reason := sprintf(
		"Wiz: %d %s severity finding(s) in this plan, budget allows %d. Remediate the %s findings listed in the Wiz step, or request an approval to override.",
		[found, level, allowed, level],
	)
}

deny contains reason if {
	some reason in wiz_severity_budget_violations
}
