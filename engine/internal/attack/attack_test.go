package attack

import (
	"bytes"
	"os"
	"testing"
)

func TestDictionary(t *testing.T) {
	for _, ok := range []string{"credential-access", "stealth", Other} {
		if !Tactic(ok) {
			t.Errorf("тактика %s", ok)
		}
	}
	for _, bad := range []string{"", "credential_access", "Credential Access"} {
		if Tactic(bad) {
			t.Errorf("тактика %q принята", bad)
		}
	}
	for _, ok := range []string{"T1110", "T1110.001", Other} {
		if !Technique(ok) {
			t.Errorf("техника %s", ok)
		}
	}
	for _, bad := range []string{"", "t1110", "T9999", "T1110.999"} {
		if Technique(bad) {
			t.Errorf("техника %q принята", bad)
		}
	}
	if Version() == "" {
		t.Error("версия")
	}
}

// Копия консоли совпадает байт в байт: кандидаты формы и проверка движка — по
// одному справочнику (обе пишет scripts/attack-enterprise.py).
func TestWebCopyIdentical(t *testing.T) {
	web, err := os.ReadFile("../../../web/src/lib/shared/attack-enterprise.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(web, raw) {
		t.Fatal("web/src/lib/shared/attack-enterprise.json отличается — запустите scripts/attack-enterprise.py")
	}
}
