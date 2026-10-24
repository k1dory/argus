package eval

import (
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func TestSanitizeExceptionsWhitelist(t *testing.T) {
	var warned []string
	exc := SanitizeExceptions(map[string][]Exception{
		"r1": {{Field: "src.ip", Value: "203.0.113.9"}, {Field: "severity", Value: "7"}, {Field: "action", Value: "http.attack"}, {Field: "node", Value: ""}},
		"r2": {{Field: "object", Value: "/health"}, {Field: "actor.name", Value: "bot"}},
	}, func(rule, field, value string) { warned = append(warned, rule+":"+field) })
	if len(exc["r1"]) != 1 || exc["r1"][0].Field != "src.ip" || len(exc["r2"]) != 2 {
		t.Fatalf("%+v", exc)
	}
	if len(warned) != 3 {
		t.Fatalf("три отброшенных исключения с предупреждением: %v", warned)
	}
	// defense in depth: excluded тоже игнорирует поля вне whitelist
	e := &model.Event{Severity: 7, Action: "http.attack", SrcIP: "203.0.113.9"}
	if excluded(e, []Exception{{Field: "severity", Value: "7"}}) {
		t.Fatal("исключение по severity не должно действовать")
	}
	if !excluded(e, []Exception{{Field: "src.ip", Value: "203.0.113.9"}}) {
		t.Fatal("исключение по src.ip действует")
	}
}

// dst.ip — в whitelist наравне с src.ip: консоль его предлагает, движок обязан
// применять, иначе «ложное» по адресу назначения молча не срабатывало бы.
func TestExceptionFieldsIncludeDstIP(t *testing.T) {
	if !ExceptionFieldAllowed("dst.ip") {
		t.Fatal("dst.ip должен быть в whitelist")
	}
	e := &model.Event{SrcIP: "203.0.113.9", DstIP: "198.51.100.5"}
	if !excluded(e, []Exception{{Field: "dst.ip", Value: "198.51.100.5"}}) {
		t.Fatal("исключение по dst.ip действует")
	}
	if excluded(e, []Exception{{Field: "dst.ip", Value: "203.0.113.9"}}) {
		t.Fatal("dst.ip не должен совпадать с src.ip")
	}
	exc := SanitizeExceptions(map[string][]Exception{"r1": {{Field: "dst.ip", Value: "198.51.100.5"}}}, nil)
	if len(exc["r1"]) != 1 {
		t.Fatalf("sanitize: %+v", exc)
	}
	want := []string{"actor.name", "dst.ip", "node", "object", "src.ip"}
	if got := ExceptionFields(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ExceptionFields: %v", got)
	}
}
