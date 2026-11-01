package analyst

import (
	"fmt"
	"strings"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Depersonalize — полное обезличивание текста инцидента независимо от профиля:
// шаблоны ПДн (email, телефон, паспорт, ИНН, карта) и облачная анонимизация
// (узлы и учётки — стабильные хеши, приватные адреса — до сети, URL без query).
// Нужен датасету и моделям решений: их записи уходят за пределы консоли
// (обучение, замеры, облачный Jev), поэтому обезличиваются всегда.
func Depersonalize(text string, inc *incidents.Incident) string {
	for _, name := range []string{"email", "phone", "passport", "inn", "card"} {
		text = patterns[name].ReplaceAllString(text, "[REDACTED:"+name+"]")
	}
	return anonymize(text, inc)
}

// DecisionState — пакет инцидента для моделей решений (System One: Laya, Jev)
// и для записи датасета: правило, уровень, теги и те же данные, что видит
// аналитик (buildData в облачном виде — без заметок дежурных у похожих
// инцидентов), обезличенные Depersonalize.
//
// Не входят: номер инцидента, статус, владелец и заметка — в них ответ
// человека (или автоматики), модель не должна его видеть.
func DecisionState(inc *incidents.Incident) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule: %s (%s), level %s\nTags: %s\n", inc.RuleTitle, inc.RuleID, inc.Level, strings.Join(inc.Tags, ", "))
	b.WriteString(buildData(inc, true))
	return Depersonalize(b.String(), inc)
}
