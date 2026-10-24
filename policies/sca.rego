# Политика по результатам Security Configuration Assessment.
# Вход (input) формирует policyd из ответа GET /sca/{agent_id}:
#   {agent_id, agent_name, policy, policy_id, score, pass, fail, invalid}
#
# Принцип: неизвестное не считается соответствующим. Отсутствующее поле входа
# или порог неверного типа в config.json дают нарушение, а не тихий пропуск.
package wazuh.sca

import rego.v1

min_score := object.get(data.config, ["sca", "min_score"], 75)

policy_name := object.get(input, "policy", "<unknown>")

# Поля берём через object.get с null по умолчанию: `not is_number(input.score)`
# при отсутствующем поле OPA переписывает в присваивание undefined, и тело
# правила становится undefined — нарушение не срабатывает. is_number(null) —
# честное false.
score := object.get(input, "score", null)

invalid := object.get(input, "invalid", null)

violations contains msg if {
	not is_number(min_score)
	msg := sprintf("policy config invalid: sca.min_score должен быть числом, получено %v", [min_score])
}

violations contains msg if {
	not is_number(score)
	msg := sprintf("SCA %q: оценка отсутствует или не число", [policy_name])
}

violations contains msg if {
	is_number(min_score)
	is_number(score)
	score < min_score
	msg := sprintf("оценка SCA %q: %d%% при минимуме %d%%", [policy_name, score, min_score])
}

violations contains msg if {
	not is_number(invalid)
	msg := sprintf("SCA %q: число невыполненных проверок (invalid) отсутствует или не число", [policy_name])
}

violations contains msg if {
	is_number(invalid)
	invalid > 0
	msg := sprintf("SCA %q: %d проверок не удалось выполнить (invalid)", [policy_name, invalid])
}

result := {
	"compliant": count(violations) == 0,
	"violations": violations,
}
