package terraform

import rego.v1

# A Wiz result whose only severity-bearing entry is marked PASSED must not be
# counted as a finding.
test_budget_clean_result_allows_run if {
	count(wiz_severity_budget_violations) == 0 with input as data.wiz_severity_budget_mock.clean
}

# The headline behaviour: Wiz says FAILED_BY_POLICY, but nothing exceeds budget,
# so this policy stays silent and the run proceeds.
test_budget_low_and_medium_within_budget_allows_run if {
	count(wiz_severity_budget_violations) == 0 with input as data.wiz_severity_budget_mock.low_only
}

test_budget_single_critical_blocks if {
	count(wiz_severity_budget_violations) == 1 with input as data.wiz_severity_budget_mock.one_critical
}

test_budget_counts_critical_correctly if {
	wiz_sev_count("CRITICAL") == 1 with input as data.wiz_severity_budget_mock.one_critical
}

# Passing entries are excluded from the counts, not just from the verdict.
test_budget_excludes_passing_entries if {
	wiz_sev_count("HIGH") == 0 with input as data.wiz_severity_budget_mock.clean
}

test_budget_medium_over_budget_blocks if {
	count(wiz_severity_budget_violations) == 1 with input as data.wiz_severity_budget_mock.medium_over_budget
}

test_budget_pre_plan_is_silent if {
	count(wiz_severity_budget_violations) == 0 with input as data.wiz_severity_budget_mock.pre_plan
}
