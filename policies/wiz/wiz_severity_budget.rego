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
# SCHEMA — pinned against a real capture
# ---------------------------------------------------------------------------
# Severity counts come from the IaC scan statistics that Wiz returns:
#
#   run_tasks.wiz.result.iac.scanStatistics
#     { infoMatches, lowMatches, mediumMatches, highMatches, criticalMatches,
#       totalMatches, filesFound, filesParsed, queriesLoaded, queriesExecuted,
#       queriesExecutionFailed }
#
# PREREQUISITE: these counters reflect findings that survived your Wiz CI/CD
# scan policy's filters. If that policy's `severityThreshold` is CRITICAL, every
# lower-severity finding is discarded before serialisation and every counter
# here reads 0 -- no Rego can recover them. Run wiz_integration_hygiene first;
# it detects exactly that misconfiguration.

package terraform

import rego.v1

wiz_sev_post_plan if {
	input.tfplan
}

wiz_sev_stats := object.get(
	input,
	["run_tasks", "wiz", "result", "iac", "scanStatistics"],
	{},
)

# How many findings of each severity this account is willing to ship.
# Tune these to make a scenario pass or fail on demand during the demo.
wiz_sev_budget := {
	"CRITICAL": 0,
	"HIGH": 0,
	"MEDIUM": 5,
	"LOW": 20,
}

wiz_sev_field := {
	"CRITICAL": "criticalMatches",
	"HIGH": "highMatches",
	"MEDIUM": "mediumMatches",
	"LOW": "lowMatches",
}

wiz_sev_count(level) := n if {
	n := object.get(wiz_sev_stats, wiz_sev_field[level], 0)
	is_number(n)
}

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
