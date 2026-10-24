package parse

import (
	"regexp"
	"strings"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Атрибуты секрета для close_match правила ci-secret-echo (rules/ci-secret-echo.yml):
// утечку закрывает только ротация или отзыв ТОГО ЖЕ секрета в ТОМ ЖЕ проекте —
// совпасть должны object (проект) и attrs.secret_id. Без attrs.secret_id
// инцидент утечки автоматикой не закрывается, только эскалируется.
//
//   - событие утечки (CI-лог в attrs.log): secret_id — имя переменной
//     («REGISTRY_TOKEN=glrt-…» → REGISTRY_TOKEN);
//   - событие ротации/отзыва (GitLab audit *_token_rotated|revoked):
//     secret_id — имя токена, token_id — его id в GitLab.
//
// Сопоставление идёт по имени: токен, который лежит в переменной CI, должен
// называться так же, как переменная (сравнение без учёта регистра). Имя
// выбирает пользователь, поэтому имя только находит инцидент, а закрывает
// его автоматикой лишь отзыв доказанно того же токена: у утечки и отзыва
// совпадают token_id, vendor/product и attrs.instance (движок, см.
// секрет-инциденты). Лог CI знает только имя переменной, token_id и instance у утечки
// нормализатор не ставит — такие инциденты по отзыву уходят в «нужна
// проверка», закрывает человек.

// leakRe — имя переменной перед значением секрета; то же условие, что у
// detection правила: (token|secret|password|api_key)=<8+ символов>.
var leakRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])([A-Za-z0-9_]*(?:token|secret|password|api_key))=[^\s*]{8,}`)

// secretChangeMarks — действие ротации или отзыва (как в close_on правила).
var secretChangeMarks = []string{"token_rotated", "token_revoked", "secret_rotated", "secret_revoked"}

// IsSecretChange — событие ротации или отзыва секрета.
func IsSecretChange(action string) bool {
	a := strings.ToLower(action)
	for _, m := range secretChangeMarks {
		if strings.Contains(a, m) {
			return true
		}
	}
	return false
}

// IsTokenCreated — создание токена GitLab (project_access_token_created,
// personal_access_token_created …): его token_id и имя — для разбора
// (какой токен и когда заведён), автозакрытие на них не опирается.
func IsTokenCreated(action string) bool {
	return strings.Contains(strings.ToLower(action), "token_created")
}

// LeakedSecretNames — имена переменных с секретами в строке лога, без
// повторов (регистр сохраняется, повтор ищется без учёта регистра).
func LeakedSecretNames(log string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range leakRe.FindAllStringSubmatch(log, -1) {
		k := strings.ToLower(m[1])
		if !seen[k] {
			seen[k] = true
			out = append(out, m[1])
		}
	}
	return out
}

// SecretAttrs проставляет attrs.secret_id и attrs.project событиям CI/CD:
// утечке в логе и ротации/отзыву секрета. Уже заданный secret_id не
// трогается. Если в одной строке лога утекло несколько секретов, secret_id не
// ставится: один ключ не опишет оба, а ротация одного закрыла бы инцидент,
// пока второй ещё действует. Такой инцидент закрывает только человек.
func SecretAttrs(e *model.Event) {
	if e.SourceClass != "cicd" {
		return
	}
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	if e.Attrs["secret_id"] != "" {
		return
	}
	var id string
	switch {
	case IsSecretChange(e.Action):
		id = firstNonEmpty(e.Attrs["token_name"], e.Attrs["variable"], e.Attrs["token_id"])
	case e.Attrs["log"] != "":
		names := LeakedSecretNames(e.Attrs["log"])
		if len(names) > 1 {
			e.Attrs["secret_names"] = strings.Join(names, ",")
		}
		if len(names) == 1 {
			id = names[0]
		}
	}
	if id == "" {
		return
	}
	e.Attrs["secret_id"] = id
	if e.Attrs["project"] == "" && e.Object != "" {
		e.Attrs["project"] = e.Object
	}
}
