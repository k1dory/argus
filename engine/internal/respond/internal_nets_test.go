package respond

import (
	"strings"
	"testing"
)

func TestInternalNetsAllowlist(t *testing.T) {
	t.Setenv("INTERNAL_NETS", "192.168.0.0/20, 185.25.9.0/24,,100.64.0.0/10")
	r := New(Config{})
	if err := r.Check("185.25.9.1"); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("свой белый блок из INTERNAL_NETS должен быть в allowlist, получено: %v", err)
	}
	if err := r.Check("94.154.43.7"); err != nil {
		t.Fatalf("чужой публичный адрес блокируется: %v", err)
	}
	if got := r.Allowlist(); len(got) != 3 {
		t.Fatalf("allowlist: %v", got)
	}
}
