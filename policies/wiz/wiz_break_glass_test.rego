package terraform

import rego.v1

test_break_glass_passing_scan_allows_run if {
	count(wiz_break_glass_violations) == 0 with input as data.wiz_break_glass_mock.passed_no_tag
}

test_break_glass_failure_without_tag_blocks if {
	count(wiz_break_glass_violations) == 1 with input as data.wiz_break_glass_mock.failed_no_tag
}

# The exception actually works outside production.
test_break_glass_tag_allows_run_in_nonprod if {
	count(wiz_break_glass_violations) == 0 with input as data.wiz_break_glass_mock.failed_with_tag_nonprod
}

# ...and is ignored inside it.
test_break_glass_tag_ignored_in_production if {
	count(wiz_break_glass_violations) == 1 with input as data.wiz_break_glass_mock.failed_with_tag_production
}

# An exception covers policy failures AND unverified scans alike.
test_break_glass_tag_covers_unreachable_scan if {
	count(wiz_break_glass_violations) == 0 with input as data.wiz_break_glass_mock.unreachable_with_tag_nonprod
}

test_break_glass_pre_plan_is_silent if {
	count(wiz_break_glass_violations) == 0 with input as data.wiz_break_glass_mock.pre_plan
}
