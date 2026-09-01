# Governed exception handling for Wiz failures.
#
# A blanket block is easy to demo and impossible to live with -- every security
# gate eventually meets a legitimate emergency. This policy shows the grown-up
# version: a Wiz failure blocks the run unless the workspace carries an explicit,
# reviewable break-glass tag, and no exception is ever honoured in production.
#
# Grant an exception:   tag the workspace `wiz-break-glass` in Scalr
# Revoke it:            remove the tag
# Audit it:             the tag lives in Scalr's workspace history, and the run
#                       that used it is permanently recorded
#
# Enforcement: hard-mandatory (see scalr-policy.hcl)
#
# Demo move: run a failing scenario, get blocked, add the tag to the workspace,
# re-run and watch it pass -- then point at the production carve-out and explain
# that the same tag would not have helped in prod.

package terraform

import rego.v1

wiz_bg_post_plan if {
	input.tfplan
}

wiz_bg_tag := "wiz-break-glass"

wiz_bg_verdict := upper(object.get(
	input,
	["run_tasks", "wiz", "status", "verdict"],
	"MISSING",
))

wiz_bg_failed if {
	wiz_bg_verdict in {"FAILED_BY_POLICY", "ERRORED", "UNREACHABLE"}
}

# tfrun.workspace.tags is an ARRAY in the current policy input -- verified
# against a real capture, where an untagged workspace serialises as [].
# Older Scalr examples show it as an object keyed by tag name, and the element
# type of the array is not documented, so all three shapes are accepted:
# ["name"], [{"name": "..."}] and {"name": ""}.
wiz_bg_granted if {
	some tag in object.get(input, ["tfrun", "workspace", "tags"], [])
	tag == wiz_bg_tag
}

wiz_bg_granted if {
	some tag in object.get(input, ["tfrun", "workspace", "tags"], [])
	is_object(tag)
	object.get(tag, "name", "") == wiz_bg_tag
}

wiz_bg_granted if {
	tags := object.get(input, ["tfrun", "workspace", "tags"], [])
	is_object(tags)
	object.get(tags, wiz_bg_tag, null) != null
}

wiz_bg_production if {
	env_type := object.get(input, ["tfrun", "workspace", "environment_type"], "")
	is_string(env_type)
	lower(env_type) == "production"
}

wiz_break_glass_violations contains reason if {
	wiz_bg_post_plan
	wiz_bg_failed
	not wiz_bg_granted

	reason := sprintf(
		"Wiz returned %s and this workspace holds no break-glass exception. Fix the findings, or have an owner tag the workspace '%s' to accept the risk explicitly.",
		[wiz_bg_verdict, wiz_bg_tag],
	)
}

# Production is never exempt, tag or no tag.
wiz_break_glass_violations contains reason if {
	wiz_bg_post_plan
	wiz_bg_failed
	wiz_bg_granted
	wiz_bg_production

	reason := sprintf(
		"Wiz returned %s. The '%s' tag is present but break-glass exceptions are not honoured in production environments. This plan must be remediated.",
		[wiz_bg_verdict, wiz_bg_tag],
	)
}

deny contains reason if {
	some reason in wiz_break_glass_violations
}
