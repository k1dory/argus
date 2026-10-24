package wazuh.sca_test

import rego.v1

import data.wazuh.sca

good_sca := {
	"agent_id": "001",
	"agent_name": "web-01",
	"policy": "CIS Ubuntu 22.04 Benchmark",
	"policy_id": "cis_ubuntu22-04",
	"score": 91,
	"pass": 180,
	"fail": 18,
	"invalid": 0,
}

test_high_score_is_compliant if {
	sca.result.compliant with input as good_sca
}

test_low_score_violates if {
	r := sca.result with input as object.union(good_sca, {"score": 42})
	not r.compliant
}

test_invalid_checks_violate if {
	r := sca.result with input as object.union(good_sca, {"invalid": 5})
	not r.compliant
}

test_min_score_comes_from_config if {
	r := sca.result with input as object.union(good_sca, {"score": 42})
		with data.config.sca.min_score as 40
	r.compliant
}

# --- валидность конфигурации и неполный вход ---

test_string_threshold_is_config_error if {
	r := sca.result with input as good_sca
		with data.config.sca.min_score as "75"
	not r.compliant
	some msg in r.violations
	startswith(msg, "policy config invalid")
}

test_missing_score_violates if {
	r := sca.result with input as object.remove(good_sca, ["score"])
	not r.compliant
	count(r.violations) == 1
}

test_missing_invalid_count_violates if {
	r := sca.result with input as object.remove(good_sca, ["invalid"])
	not r.compliant
}

test_empty_input_is_not_compliant if {
	r := sca.result with input as {}
	not r.compliant
	count(r.violations) == 2
}
