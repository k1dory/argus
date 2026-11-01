package scripts_test

// scripts/asn-update.sh на временных каталогах, источник — file://. Сбой любой
// проверки оставляет прежний файл; удачное обновление заменяет его целиком.

import (
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gz(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(body))
	w.Close()
	return b.Bytes()
}

func runASNUpdate(t *testing.T, dir, src string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "asn-update.sh", dir, "file://"+src)
	cmd.Env = append(os.Environ(), "ASN_DB_MIN_ROWS=2")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestASNUpdate(t *testing.T) {
	good := "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n45.33.0.0\t45.33.127.255\t63949\tUS\tAKAMAI\n"
	dir, srcDir := t.TempDir(), t.TempDir()
	dest := filepath.Join(dir, "ip2asn-combined.tsv.gz")
	write := func(name string, data []byte) string {
		p := filepath.Join(srcDir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if out, err := runASNUpdate(t, dir, write("good.gz", gz(t, good))); err != nil {
		t.Fatalf("удачное обновление: %v\n%s", err, out)
	}
	installed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o644 {
		t.Errorf("права %v: коллектор в контейнере должен читать файл", fi.Mode().Perm())
	}

	full := gz(t, good)
	for name, data := range map[string][]byte{
		"не gzip":      []byte(good),
		"обрезан":      full[:len(full)-6],
		"мало строк":   gz(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n"),
		"чужой формат": gz(t, "a,b,c\nd,e,f\n"),
	} {
		out, err := runASNUpdate(t, dir, write(strings.ReplaceAll(name, " ", "_"), data))
		if err == nil {
			t.Errorf("%s: принято\n%s", name, out)
		}
		if now, _ := os.ReadFile(dest); !bytes.Equal(now, installed) {
			t.Errorf("%s: прежний файл заменён", name)
		}
	}
	if _, err := runASNUpdate(t, dir, filepath.Join(srcDir, "absent.gz")); err == nil {
		t.Error("недоступный источник принят")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".ip2asn.*")); len(left) > 0 {
		t.Errorf("временные файлы не убраны: %v", left)
	}
}
