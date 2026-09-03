package terraform

import rego.v1

# The exact observed run: 07-critical-exposure, WARN_BY_POLICY, one AUDIT-mode
# policy match. Wiz let it through; this policy does not.
test_failed_policies_blocks_real_audit_mode_capture if {
	count(wiz_failed_policies_violations) == 1 with input as data.wiz_failed_policies_mock.warn_audit_mode
}

test_failed_policies_clean_scan_allows_run if {
	count(wiz_failed_policies_violations) == 0 with input as data.wiz_failed_policies_mock.clean
}

test_failed_policies_single_match_blocks if {
	count(wiz_failed_policies_violations) == 1 with input as data.wiz_failed_policies_mock.one_failed_policy
}

test_failed_policies_reports_each_policy_separately if {
	count(wiz_failed_policies_violations) == 2 with input as data.wiz_failed_policies_mock.two_failed_policies
}

# A match Wiz already ignored is not a violation -- respect the ignore rather
# than second-guessing an accepted risk.
test_failed_policies_respects_ignore_reason if {
	count(wiz_failed_policies_violations) == 0 with input as data.wiz_failed_policies_mock.ignored_by_reason
}

test_failed_policies_respects_matched_ignore_rules if {
	count(wiz_failed_policies_violations) == 0 with input as data.wiz_failed_policies_mock.ignored_by_rule
}

test_failed_policies_pre_plan_is_silent if {
	count(wiz_failed_policies_violations) == 0 with input as data.wiz_failed_policies_mock.pre_plan
}
