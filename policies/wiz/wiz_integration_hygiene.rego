# Guard the guard — is the Wiz integration actually configured to catch anything?
#
# A security gate that silently passes everything is worse than no gate, because
# it manufactures confidence. This policy inspects the Wiz CI/CD scan policies
# that were evaluated on the run and fails if they cannot, even in principle,
# stop a bad plan.
#
# Enforcement: hard-mandatory (see scalr-policy.hcl)
#
# This is not hypothetical. On a stock Wiz tenant the built-in IaC policy ships
# as:
#
#     params.severityThreshold        = "CRITICAL"
#     policyLifecycleEnforcements     = [{CLI, AUDIT}, {CODE, AUDIT}, ...]
#
# With those defaults a plan containing an internet-facing database, wide-open
# security groups and wildcard IAM admin returns PASSED_BY_POLICY and an empty
# Failed Policies list. The findings are discarded before the result is
# serialised, so scanStatistics reads all zeroes and no downstream OPA policy
# can recover them. Everything looks green.
#
# Schema — verified against a real capture:
#   run_tasks.wiz.policies[]
#     .name, .type ("IAC" | "VULNERABILITIES" | "SECRETS" | ...)
#     .params.severityThreshold ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL")
#     .policyLifecycleEnforcements[] { enforcementMethod: "AUDIT"|"BLOCK",
#                                      deploymentLifecycle: "CLI"|"CODE"|... }

package terraform

import rego.v1

wiz_hyg_post_plan if {
	input.tfplan
}

wiz_hyg_policies := object.get(input, ["run_tasks", "wiz", "policies"], [])

wiz_hyg_iac_policies := [p |
	some p in wiz_hyg_policies
	upper(object.get(p, "type", "")) == "IAC"
]

# Thresholds permissive enough to surface the misconfigurations that matter.
# CRITICAL alone is too narrow: most Terraform IaC rules are rated High or below.
wiz_hyg_allowed_thresholds := {"HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO"}

# Set to false if you enforce through OPA (wiz_severity_budget) rather than
# through Wiz itself. With AUDIT, Wiz reports findings and Scalr decides --
# a valid design, but only once severityThreshold is permissive enough that
# findings actually reach the policy input.
wiz_hyg_require_blocking := true

wiz_integration_hygiene_violations contains reason if {
	wiz_hyg_post_plan
	count(wiz_hyg_iac_policies) == 0

	reason := "Wiz: no IaC scan policy was evaluated on this run, so Terraform misconfigurations cannot fail it. Add an IaC CI/CD scan policy to the Wiz connection."
}

wiz_integration_hygiene_violations contains reason if {
	wiz_hyg_post_plan

	some p in wiz_hyg_iac_policies
	threshold := upper(object.get(p, ["params", "severityThreshold"], ""))
	not threshold in wiz_hyg_allowed_thresholds

	reason := sprintf(
		"Wiz: IaC policy '%s' has severityThreshold=%s, which discards every finding below that level before Scalr ever sees it. Most Terraform misconfiguration rules are rated High or lower. Lower the threshold to HIGH or below.",
		[object.get(p, "name", "<unnamed>"), threshold],
	)
}

wiz_integration_hygiene_violations contains reason if {
	wiz_hyg_post_plan
	wiz_hyg_require_blocking

	some p in wiz_hyg_iac_policies
	some enforcement in object.get(p, "policyLifecycleEnforcements", [])
	upper(object.get(enforcement, "deploymentLifecycle", "")) == "CLI"
	upper(object.get(enforcement, "enforcementMethod", "")) == "AUDIT"

	reason := sprintf(
		"Wiz: IaC policy '%s' is set to AUDIT for the CLI lifecycle, so it reports findings but never fails the scan. Set it to BLOCK, or enforce through OPA instead and set wiz_hyg_require_blocking to false.",
		[object.get(p, "name", "<unnamed>")],
	)
}

deny contains reason if {
	some reason in wiz_integration_hygiene_violations
}
