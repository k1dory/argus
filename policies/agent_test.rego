package wazuh.agent_test

import rego.v1

import data.wazuh.agent

fresh_agent := {
	"id": "001",
	"name": "web-01",
	"status": "active",
	"version": "Wazuh v4.12.0",
	"stale_seconds": 30,
	"os_platform": "ubuntu",
}

test_active_fresh_agent_is_compliant if {
	agent.result.compliant with input as fresh_agent
}

test_disconnected_agent_violates if {
	r := agent.result with input as object.union(fresh_agent, {"status": "disconnected"})
	not r.compliant
	count(r.violations) == 1
}

test_stale_keepalive_violates if {
	r := agent.result with input as object.union(fresh_agent, {"stale_seconds": 3600})
	not r.compliant
}

test_old_version_violates if {
	r := agent.result with input as object.union(fresh_agent, {"version": "Wazuh v4.2.0"})
	not r.compliant
}

test_unparseable_version_violates if {
	r := agent.result with input as object.union(fresh_agent, {"version": "custom-build"})
	not r.compliant
	count(r.violations) == 1
}

test_unknown_keepalive_violates if {
	r := agent.result with input as object.union(fresh_agent, {"stale_seconds": -1})
	not r.compliant
}

test_threshold_comes_from_config if {
	r := agent.result with input as object.union(fresh_agent, {"stale_seconds": 3600})
		with data.config.agent.max_stale_seconds as 7200
	r.compliant
}

# --- валидность конфигурации и неполный вход ---

test_string_threshold_is_config_error if {
	r := agent.result with input as fresh_agent
		with data.config.agent.max_stale_seconds as "600"
	not r.compliant
	some msg in r.violations
	startswith(msg, "policy config invalid")
}

test_numeric_min_version_is_config_error if {
	r := agent.result with input as fresh_agent
		with data.config.agent.min_version as 4.9
	not r.compliant
	some msg in r.violations
	startswith(msg, "policy config invalid")
}

test_non_semver_min_version_is_config_error if {
	r := agent.result with input as fresh_agent
		with data.config.agent.min_version as "latest"
	not r.compliant
	some msg in r.violations
	startswith(msg, "policy config invalid")
}

test_missing_stale_seconds_violates if {
	r := agent.result with input as object.remove(fresh_agent, ["stale_seconds"])
	not r.compliant
	"время последнего keepalive неизвестно" in r.violations
}

test_empty_input_is_not_compliant if {
	r := agent.result with input as {}
	not r.compliant
	"статус агента неизвестен" in r.violations
	"версия агента неизвестна" in r.violations
}
