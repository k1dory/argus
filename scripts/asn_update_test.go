package scripts_test

// scripts/asn-update.sh на временных каталогах, источник — file://. Сбой любой
// проверки оставляет прежний файл; удачное обновление заменяет его целиком.

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "asn-update.sh", dir, "file://"+src)
	// Only local fixtures; do not inherit proxies, curl configuration or secrets.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(), "LC_ALL=C", "ASN_DB_MIN_ROWS=2"}
	cmd.WaitDelay = time.Second
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

// A valid gzip container and five TSV columns do not make a usable database.
// Once the updater replaces the on-disk file, a collector restart loses the
// last good table even though a running collector can keep its old snapshot.
func TestPR56ASNUpdatePreservesLastUsableTable(t *testing.T) {
	good := "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n"
	for name, broken := range map[string]string{
		"invalid_address": "invalid\t1.0.0.255\t13335\tUS\tX\n" +
			"8.8.8.0\t8.8.8.255\t15169\tUS\tY\n",
		"invalid_asn": "1.0.0.0\t1.0.0.255\t4294967296\tUS\tX\n" +
			"8.8.8.0\t8.8.8.255\t15169\tUS\tY\n",
		"reversed_range": "1.0.0.255\t1.0.0.0\t13335\tUS\tX\n" +
			"8.8.8.0\t8.8.8.255\t15169\tUS\tY\n",
		"unsorted_ranges": "8.8.8.0\t8.8.8.255\t15169\tUS\tY\n" +
			"1.0.0.0\t1.0.0.255\t13335\tUS\tX\n",
		"overlapping_ipv4": "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n" +
			"1.0.0.128\t1.0.1.255\t15169\tUS\tY\n",
		"overlapping_ipv6": "2606:4700::\t2606:4700::ff\t13335\tUS\tX\n" +
			"2606:4700::80\t2606:4700::1ff\t15169\tUS\tY\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			dest := filepath.Join(dir, "ip2asn-combined.tsv.gz")
			previous := gz(t, good)
			if err := os.WriteFile(dest, previous, 0o644); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join(t.TempDir(), "broken.tsv.gz")
			if err := os.WriteFile(src, gz(t, broken), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := runASNUpdate(t, dir, src)
			if err == nil {
				t.Errorf("unusable database reported as a successful update:\n%s", out)
			}
			current, err := os.ReadFile(dest)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(current, previous) {
				t.Error("the last usable database on disk was replaced; after restart ASN enrichment is lost")
			}
		})
	}
}

// mv interprets a destination symlink to a directory as a target directory.
// The updater must not write outside its database directory or claim success
// with ip2asn-combined.tsv.gz still pointing to a directory. All targets in
// this regression are disposable fixtures owned by the test user.
func TestPR56ASNUpdateDoesNotFollowDestinationDirectorySymlink(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	dest := filepath.Join(dir, "ip2asn-combined.tsv.gz")
	if err := os.Symlink(outside, dest); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "good.tsv.gz")
	good := gz(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n8.8.8.0\t8.8.8.255\t15169\tUS\tY\n")
	if err := os.WriteFile(src, good, 0o600); err != nil {
		t.Fatal(err)
	}
	out, runErr := runASNUpdate(t, dir, src)
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("update wrote %d file(s) through the destination symlink outside its database directory", len(entries))
	}
	// Either reject the symlink or replace the link itself with the database.
	if runErr == nil {
		fi, err := os.Lstat(dest)
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("update reported success without installing a regular database: stat=%v, err=%v\n%s", fi, err, out)
		}
		installed, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(installed, good) {
			t.Fatalf("installed database does not match download: %v", err)
		}
	}
}

// Positive control: replacing a symlink to a regular file must leave the
// pointed-to file intact (the directory-symlink case above behaves differently).
func TestPR56ASNUpdateLeavesRegularSymlinkTargetIntact(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "unrelated-file")
	previous := []byte("unrelated fixture; must remain unchanged")
	if err := os.WriteFile(outside, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ip2asn-combined.tsv.gz")); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "good.tsv.gz")
	if err := os.WriteFile(src, gz(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n8.8.8.0\t8.8.8.255\t15169\tUS\tY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = runASNUpdate(t, dir, src) // Rejecting the symlink is also safe.
	current, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(current, previous) {
		t.Fatalf("regular symlink target was modified: %v", err)
	}
}
