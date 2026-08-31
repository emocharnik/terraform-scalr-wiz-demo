package terraform

import rego.v1

test_verdict_passed_allows_run if {
	count(wiz_verdict_violations) == 0 with input as data.wiz_verdict_mock.passed
}

test_verdict_failed_by_policy_blocks if {
	count(wiz_verdict_violations) == 1 with input as data.wiz_verdict_mock.failed_by_policy
}

test_verdict_errored_blocks if {
	count(wiz_verdict_violations) == 1 with input as data.wiz_verdict_mock.errored
}

test_verdict_unreachable_blocks if {
	count(wiz_verdict_violations) == 1 with input as data.wiz_verdict_mock.unreachable
}

# Fail closed: a post-plan run with no Wiz result at all is still blocked.
test_verdict_missing_result_blocks if {
	count(wiz_verdict_violations) == 1 with input as data.wiz_verdict_mock.no_wiz_result
}

# The pre-plan guard: no tfplan means the scan has not run yet, so the policy
# must stay silent rather than block the run before Wiz ever sees it.
test_verdict_pre_plan_is_silent if {
	count(wiz_verdict_violations) == 0 with input as data.wiz_verdict_mock.pre_plan
}
