# Baseline Wiz enforcement — the "policy check mode" equivalent of auto-fail.
#
# Scalr publishes the validated Wiz run-task result at `input.run_tasks.wiz`
# during post-plan policy evaluation. This policy reads only the one field Scalr
# documents as stable -- `status.verdict` -- so it keeps working even as Wiz
# evolves the nested result schema.
#
# Enforcement: hard-mandatory (see scalr-policy.hcl)
#
# Demo note: enable ONLY this policy to reproduce auto-fail behaviour, then add
# wiz_severity_budget to show the same Wiz result producing a different outcome.

package terraform

import rego.v1

# `input.run_tasks` is populated at the post-plan stage only. Without this guard
# a pre-plan evaluation would see no Wiz result and block every run before the
# scan has had a chance to run at all.
wiz_verdict_post_plan if {
	input.tfplan
}

# Verdicts observed from a real Scalr run, as printed in the Wiz step's
# "Scan summary: Verdict:" line:
#
#   PASSED_BY_POLICY   every evaluated Wiz CI/CD policy passed
#   FAILED_BY_POLICY   at least one evaluated policy failed
#   ERRORED            the scan started but did not finish
#   UNREACHABLE        Scalr could not reach the Wiz API
#
# This is a deny-list, deliberately: any verdict not named below is treated as a
# pass, so a new Wiz verdict string cannot silently block every run in the
# account. The trade-off is the MISSING rule at the bottom, which is what keeps
# the policy fail-closed when no result is attached at all.
wiz_verdict_value := upper(object.get(
	input,
	["run_tasks", "wiz", "status", "verdict"],
	"MISSING",
))

wiz_verdict_violations contains reason if {
	wiz_verdict_post_plan
	wiz_verdict_value == "FAILED_BY_POLICY"

	reason := "Wiz: the planned infrastructure failed one or more Wiz CI/CD scan policies. Open the Wiz step on this run for the finding list, fix the Terraform, and push again."
}

wiz_verdict_violations contains reason if {
	wiz_verdict_post_plan
	wiz_verdict_value == "ERRORED"

	reason := "Wiz: the scan started but did not complete, so this plan is unverified. Blocking rather than assuming it is clean. Check the Wiz step output and the integration credentials."
}

wiz_verdict_violations contains reason if {
	wiz_verdict_post_plan
	wiz_verdict_value == "UNREACHABLE"

	reason := "Wiz: Scalr could not reach the Wiz API, so this plan is unverified. Blocking rather than assuming it is clean. Check the Wiz connection under Integrations."
}

# Fail closed: a plan that was never scanned is not a plan that passed.
# If you link this policy group to environments outside the Wiz integration's
# scope, disable this rule -- those runs legitimately carry no Wiz result.
wiz_verdict_violations contains reason if {
	wiz_verdict_post_plan
	wiz_verdict_value == "MISSING"

	reason := "Wiz: no scan result was attached to this run. Confirm the Wiz integration is enabled for this environment."
}

deny contains reason if {
	some reason in wiz_verdict_violations
}
