package terraform

import rego.v1

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

test_budget_reads_counts_from_scan_statistics if {
	wiz_sev_count("CRITICAL") == 1 with input as data.wiz_severity_budget_mock.one_critical
	wiz_sev_count("MEDIUM") == 6 with input as data.wiz_severity_budget_mock.medium_over_budget
}

test_budget_medium_over_budget_blocks if {
	count(wiz_severity_budget_violations) == 1 with input as data.wiz_severity_budget_mock.medium_over_budget
}

# The trap this repo hit in practice: Wiz filtered every finding before
# serialising, so all counters read zero and this policy is blind. It must not
# claim the plan is safe -- that is wiz_integration_hygiene's job to catch.
test_budget_is_blind_when_findings_were_filtered_away if {
	count(wiz_severity_budget_violations) == 0 with input as data.wiz_severity_budget_mock.filtered_away
}

test_budget_pre_plan_is_silent if {
	count(wiz_severity_budget_violations) == 0 with input as data.wiz_severity_budget_mock.pre_plan
}
