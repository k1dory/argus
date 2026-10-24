package listen

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
)

// Counters — счётчики приёмников для /metrics: паники, переполнения кадров,
// отвергнутые соединения. Один экземпляр на процесс.
type Counters struct {
	Panics       atomic.Uint64 // перехваченных паник (парсеры, хендлеры)
	Oversize     atomic.Uint64 // кадров/строк больше лимита — соединение закрыто
	ConnRejected atomic.Uint64 // TCP/TLS-соединений отвергнуто по лимиту
	ActiveConns  atomic.Int64  // открытых TCP/TLS-соединений сейчас
}

var Metrics = &Counters{}

// Guard выполняет f, перехватывая панику: одна кривая строка или пакет не
// должны валить процесс. Паника — в лог с трассой и в счётчик.
// http.ErrAbortHandler — штатный способ net/http оборвать ответ (клиент ушёл):
// пробрасывается дальше без трассы и без счётчика.
func Guard(where string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			if r == http.ErrAbortHandler {
				panic(r)
			}
			Metrics.Panics.Add(1)
			stack := debug.Stack()
			if len(stack) > 4<<10 {
				stack = stack[:4<<10]
			}
			slog.Error("panic перехвачен", "where", where, "panic", fmt.Sprint(r), "stack", string(stack))
		}
	}()
	f()
}

// SafeGo — go f() под Guard.
func SafeGo(where string, f func()) {
	go Guard(where, f)
}
