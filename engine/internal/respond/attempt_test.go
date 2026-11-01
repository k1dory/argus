package respond

import (
	"context"
	"errors"
	"testing"
)

func TestCanonicalIP(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:192.0.2.10": "192.0.2.10",
		" 192.0.2.10 ":      "192.0.2.10",
		"2001:0DB8:0001:0000:0000:0000:0000:0007": "2001:db8:1::7",
		"fe80::1%eth0": "fe80::1",
	} {
		if got, ok := CanonicalIP(in); !ok || got != want {
			t.Errorf("%q: %q %v, ожидалось %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "host.example", "192.0.2.300"} {
		if _, ok := CanonicalIP(bad); ok {
			t.Errorf("%q принят", bad)
		}
	}
}

// Attempt: режим — снимок вызывающего; резерв — под замком адреса и перед
// исполнителями; его ошибка — исполнители не вызываются; очередь повторов не растёт.
func TestAttemptReserveBeforeExecutor(t *testing.T) {
	srv, blocks, _ := newNGFW(t)
	r := New(cfg(srv, ModeIDS)) // режим респондера не важен: Attempt берёт переданный
	ctx := context.Background()
	reserves := 0
	reserve := func() error {
		reserves++
		if blocks.Load() != 0 {
			t.Fatal("резерв после исполнителя")
		}
		return nil
	}
	if _, out, err := r.Attempt(ctx, ModeSimulate, "192.0.2.10", "INC-1", "x", 0, reserve); err != nil || out != OutcomeSimulated || reserves != 0 || blocks.Load() != 0 {
		t.Fatalf("simulate: %v %v резервов %d", out, err, reserves)
	}
	if _, out, err := r.Attempt(ctx, ModeIPS, "203.0.113.5", "INC-1", "x", 0, reserve); err != nil || out != OutcomeRefused || reserves != 0 {
		t.Fatalf("allowlist: %v %v", out, err)
	}
	if _, out, err := r.Attempt(ctx, ModeIPS, "192.0.2.10", "INC-1", "x", 0, func() error { return errors.New("journal down") }); out != OutcomeReserveFailed || err == nil || blocks.Load() != 0 {
		t.Fatalf("резерв не записан: %v %v блоков %d", out, err, blocks.Load())
	}
	if _, out, err := r.Attempt(ctx, ModeIPS, "::ffff:192.0.2.10", "INC-1", "x", 0, reserve); err != nil || out != OutcomeBlocked || reserves != 1 || blocks.Load() != 1 {
		t.Fatalf("ips: %v %v резервов %d блоков %d", out, err, reserves, blocks.Load())
	}
	if _, out, _ := r.Attempt(ctx, ModeIPS, "192.0.2.10", "INC-2", "x", 0, reserve); out != OutcomeNoop || reserves != 1 {
		t.Fatalf("уже заблокирован — без резерва и исполнителя: %v резервов %d", out, reserves)
	}
	if _, _, err := r.Attempt(ctx, ModeIDS, "192.0.2.11", "INC-3", "x", 0, reserve); err == nil {
		t.Fatal("ids: попытка не выполняется")
	}
	if r.Pending() != 0 {
		t.Fatal("Attempt не ставит в очередь повторов")
	}
}

func TestAttemptFailedDoesNotQueue(t *testing.T) {
	r := New(Config{Mode: ModeIPS, HTTP: []HTTPAction{{Name: "down", URL: "http://127.0.0.1:1/block"}}})
	_, out, err := r.Attempt(context.Background(), ModeIPS, "192.0.2.10", "INC-1", "x", 0, func() error { return nil })
	if err != nil || out != OutcomeFailed || r.Pending() != 0 || len(r.Active()) != 0 {
		t.Fatalf("отказ: %v %v очередь %d", out, err, r.Pending())
	}
	if MaxAttempts != 4 || RetryDelay(1) != retryBackoff[0] || RetryDelay(9) != retryBackoff[len(retryBackoff)-1] {
		t.Fatal("расписание повторов")
	}
}
