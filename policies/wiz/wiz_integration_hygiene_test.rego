package terraform

import rego.v1

# The real observed configuration: CRITICAL threshold + AUDIT enforcement.
# Both are wrong, so both are reported.
test_hygiene_stock_defaults_flags_threshold_and_audit if {
	count(wiz_integration_hygiene_violations) == 2 with input as data.wiz_integration_hygiene_mock.stock_defaults
}

test_hygiene_well_configured_policy_is_silent if {
	count(wiz_integration_hygiene_violations) == 0 with input as data.wiz_integration_hygiene_mock.well_configured
}

# Threshold fixed but still AUDIT -- fine if you enforce via OPA, flagged by
# default because wiz_hyg_require_blocking is true.
test_hygiene_audit_only_is_flagged_by_default if {
	count(wiz_integration_hygiene_violations) == 1 with input as data.wiz_integration_hygiene_mock.threshold_ok_audit_only
}

test_hygiene_missing_iac_policy_blocks if {
	count(wiz_integration_hygiene_violations) == 1 with input as data.wiz_integration_hygiene_mock.no_iac_policy
}

test_hygiene_pre_plan_is_silent if {
	count(wiz_integration_hygiene_violations) == 0 with input as data.wiz_integration_hygiene_mock.pre_plan
}
