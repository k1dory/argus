package sink

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// PR #27: short() отрезает только несколько известных хвостов ClickHouse,
// но данные могут находиться в начале сообщения, до этих хвостов.
// Проверяем настоящий deadLetter logger на уровне info, а не разрешённый
// debug-вывод raw; запись таблицы отказов остаётся в mockCH без сети.
func TestPR27DeadLetterDoesNotLogClickHouseExceptionData(t *testing.T) {
	const marker = "PrivateCollectorEventFixture"
	err := parseError("events", 400, "6",
		"Code: 6. DB::Exception: Cannot parse string '"+marker+"' as UInt8: syntax error at position 0. (CANNOT_PARSE_TEXT)")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	m := &mockCH{}
	w, stats := newTestWriter(m)
	if !w.deadLetter([]any{ev(marker)}, err) {
		t.Fatal("fixture dead letter was not persisted")
	}
	if stats.DeadLetter.Load() != 1 || len(m.rejects) != 1 {
		t.Fatal("fixture did not exercise the actual dead-letter path")
	}
	if !strings.Contains(m.rejects[0].Raw, marker) {
		t.Fatal("control: original data must remain in the restricted reject table")
	}
	if !strings.Contains(logs.String(), "dead letter") || !strings.Contains(logs.String(), "code 6") {
		t.Fatal("the logger must retain operation and error code")
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatal("info/error logs contain the value quoted by ClickHouse despite short()")
	}
}
