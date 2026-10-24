# Политика соответствия для агентов Wazuh.
# Вход (input) формирует policyd из ответа GET /agents:
#   {id, name, status, version, stale_seconds, os_platform}
# Пороговые значения задаются в config.json рядом с политикой.
#
# Принцип: неизвестное не считается соответствующим. Отсутствующее поле входа
# или порог неверного типа в config.json дают нарушение, а не тихий пропуск.
package wazuh.agent

import rego.v1

max_stale_seconds := object.get(data.config, ["agent", "max_stale_seconds"], 600)

min_version := object.get(data.config, ["agent", "min_version"], "v4.9.0")

# Поле берём через object.get с null: `not is_number(input.stale_seconds)` при
# отсутствующем поле OPA переписывает в присваивание undefined, и тело правила
# становится undefined — нарушение не срабатывает. is_number(null) — честное false.
stale_seconds := object.get(input, "stale_seconds", null)

# --- валидность конфигурации ---

violations contains msg if {
	not is_number(max_stale_seconds)
	msg := sprintf("policy config invalid: agent.max_stale_seconds должен быть числом, получено %v", [max_stale_seconds])
}

violations contains msg if {
	not is_string(min_version)
	msg := sprintf("policy config invalid: agent.min_version должен быть строкой, получено %v", [min_version])
}

violations contains msg if {
	is_string(min_version)
	not min_version_number
	msg := sprintf("policy config invalid: agent.min_version %q не содержит semver", [min_version])
}

# --- статус и keepalive ---

violations contains msg if {
	not input.status
	msg := "статус агента неизвестен"
}

violations contains msg if {
	input.status != "active"
	msg := sprintf("агент не активен: статус %q", [input.status])
}

violations contains msg if {
	input.status == "active"
	is_number(max_stale_seconds)
	is_number(stale_seconds)
	stale_seconds > max_stale_seconds
	msg := sprintf("keepalive устарел на %d с (порог %d с)", [stale_seconds, max_stale_seconds])
}

# stale_seconds < 0 — policyd не смог разобрать lastKeepAlive; отсутствие
# поля — тоже неизвестно. Неизвестное время последнего ответа не считается свежим.
violations contains msg if {
	input.status == "active"
	not is_number(stale_seconds)
	msg := "время последнего keepalive неизвестно"
}

violations contains msg if {
	input.status == "active"
	is_number(stale_seconds)
	stale_seconds < 0
	msg := "время последнего keepalive неизвестно"
}

# --- версия ---

violations contains msg if {
	not input.version
	msg := "версия агента неизвестна"
}

# Версия приходит в виде "Wazuh v4.7.2" — вытаскиваем semver явно;
# непарсибельная строка — отдельное нарушение, а не тихий пропуск проверки.
parsed_version := m[1] if {
	is_string(input.version)
	m := regex.find_all_string_submatch_n(`(\d+\.\d+\.\d+)`, input.version, 1)[0]
}

min_version_number := m[1] if {
	is_string(min_version)
	m := regex.find_all_string_submatch_n(`(\d+\.\d+\.\d+)`, min_version, 1)[0]
}

violations contains msg if {
	input.version
	not parsed_version
	msg := sprintf("не удалось разобрать версию агента %v", [input.version])
}

violations contains msg if {
	parsed_version
	min_version_number
	semver.compare(parsed_version, min_version_number) < 0
	msg := sprintf("версия агента %s ниже минимальной %s", [parsed_version, min_version_number])
}

result := {
	"compliant": count(violations) == 0,
	"violations": violations,
}
