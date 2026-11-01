package scripts_test

// scripts/asn-update.sh на временных каталогах, источник — file://. Сбой любой
// проверки оставляет прежний файл; удачное обновление заменяет его целиком.

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain собирает настоящий коллектор: скрипт проверяет таблицу его же
// `collector asn-check`, найденным в PATH.
func TestMain(m *testing.M) {
	bin, err := os.MkdirTemp("", "asn-update-bin")
	if err != nil {
		panic(err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(bin, "collector"), "./cmd/collector")
	build.Dir = filepath.Join("..", "collector")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		panic("сборка collector: " + err.Error())
	}
	os.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	code := m.Run()
	os.RemoveAll(bin)
	os.Exit(code)
}

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

// Отказ проверяющего (ASN_CHECK) — таблица не заменяется, даже годная по форме.
func TestASNUpdateRejectedByChecker(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "ip2asn-combined.tsv.gz")
	previous := gz(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n8.8.8.0\t8.8.8.255\t15169\tUS\tY\n")
	if err := os.WriteFile(dest, previous, 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "next.gz")
	if err := os.WriteFile(src, gz(t, "9.9.9.0\t9.9.9.255\t19281\tUS\tQ\n45.33.0.0\t45.33.127.255\t63949\tUS\tA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "asn-update.sh", dir, "file://"+src)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "ASN_DB_MIN_ROWS=2", "ASN_CHECK=false"}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("отказ проверяющего проигнорирован:\n%s", out)
	}
	if now, _ := os.ReadFile(dest); !bytes.Equal(now, previous) {
		t.Error("таблица заменена вопреки проверяющему")
	}
}

// PR #57: exercise the Docker fallback, which the earlier tests bypass by
// putting collector in PATH. Only Docker is replaced: validation still runs
// the real collector built by TestMain, and curl reads a local file:// fixture.
// This double implements the relevant docker run -v contract: a source such
// as data/.ip2asn.X is a volume name, not a host path, and '/' is invalid in a
// volume name. Absolute paths and ./relative paths are supported by the CLI.
// https://github.com/docker/cli/blob/v27.5.1/cli/command/container/opts.go
// https://github.com/moby/moby/blob/v27.5.1/volume/mounts/linux_parser.go
const pr57DockerStub = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$PR57_DOCKER_LOG"
case "$1" in
  compose)
    [[ $# == 6 && $2 == --project-directory && $3 == "$PR57_ROOT" && $4 == ps && $5 == -q && $6 == collector ]]
    printf '%s\n' fixture-collector
    ;;
  inspect)
    [[ $# == 4 && $2 == -f && $3 == '{{.Image}}' && $4 == fixture-collector ]]
    printf '%s\n' sha256:fixture-image
    ;;
  run)
    shift
    source='' min='' network='' readonly=0
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --rm) shift ;;
        --read-only) readonly=1; shift ;;
        --network) network=$2; shift 2 ;;
        -e)
          [[ $2 == ASN_DB_MIN_ROWS=* ]]
          min=${2#ASN_DB_MIN_ROWS=}; shift 2
          ;;
        -v)
          [[ $2 == *:/check.tsv.gz:ro ]]
          source=${2%:/check.tsv.gz:ro}; shift 2
          ;;
        sha256:fixture-image) shift; break ;;
        *) printf 'unexpected docker option: %s\n' "$1" >&2; exit 125 ;;
      esac
    done
    [[ $network == none && $readonly == 1 && -n $min && -n $source ]]
    [[ $# == 2 && $1 == asn-check && $2 == /check.tsv.gz ]]
    case "$source" in
      /*|./*) ;;
      *) printf 'invalid volume name (expected a host path): %s\n' "$source" >&2; exit 125 ;;
    esac
    export ASN_DB_MIN_ROWS=$min
    exec "$PR57_COLLECTOR" asn-check "$source"
    ;;
  *) printf 'unexpected docker command: %s\n' "$1" >&2; exit 125 ;;
esac
`

type pr57ASNUpdateFixture struct {
	root, dir, source, dest, collector, dockerLog string
	env                                           []string
}

func newPR57ASNUpdateFixture(t *testing.T, composeMin int) *pr57ASNUpdateFixture {
	t.Helper()
	root := t.TempDir()
	// Resolve macOS's /var -> /private/var so the shell's pwd and the fixture
	// agree when the updater determines its Compose project directory.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	f := &pr57ASNUpdateFixture{root: root, dir: filepath.Join(root, "data"),
		source: filepath.Join(root, "download.gz"), dockerLog: filepath.Join(root, "docker.log")}
	f.dest = filepath.Join(f.dir, "ip2asn-combined.tsv.gz")
	f.collector, err = exec.LookPath("collector")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{bin, f.dir, filepath.Join(root, "scripts")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("asn-update.sh")
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		filepath.Join(root, "scripts", "asn-update.sh"): script,
		filepath.Join(bin, "docker"):                    []byte(pr57DockerStub),
	} {
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Model the documented Compose/Ansible configuration, without exporting
	// it to the cron process. Only dummy values are ever written or inherited.
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(fmt.Sprintf("ASN_DB_MIN_ROWS=%d\n", composeMin)), 0o600); err != nil {
		t.Fatal(err)
	}
	// An allowlisted PATH forces the fallback and prevents access to a real
	// Docker daemon, even on developer machines with collector installed.
	for _, name := range []string{"bash", "dirname", "mktemp", "curl", "gzip", "chmod", "mv", "rm"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	f.env = []string{"PATH=" + bin, "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir(), "LC_ALL=C",
		"PR57_ROOT=" + root, "PR57_COLLECTOR=" + f.collector, "PR57_DOCKER_LOG=" + f.dockerLog}
	return f
}

func pr57ASNTable(t *testing.T, rows int, org string) []byte {
	t.Helper()
	var body strings.Builder
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&body, "1.0.%d.%d\t1.0.%d.%d\t64500\tZZ\t%s\n", i/256, i%256, i/256, i%256, org)
	}
	return gz(t, body.String())
}

func (f *pr57ASNUpdateFixture) run(t *testing.T, dir string, extraEnv ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(f.root, "bin", "bash"), "scripts/asn-update.sh", dir, "file://"+f.source)
	cmd.Dir = f.root
	cmd.Env = append(append([]string{}, f.env...), extraEnv...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *pr57ASNUpdateFixture) check(t *testing.T, path string, min int) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.collector, "asn-check", path)
	cmd.Env = append(append([]string{}, f.env...), fmt.Sprintf("ASN_DB_MIN_ROWS=%d", min))
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A larger .env threshold must protect the last usable table; a smaller one
// must permit the configured small feed. In cron, .env is read by Compose,
// not exported into the parent updater's environment.
func TestPR57ASNUpdateUsesComposeMinRows(t *testing.T) {
	for _, tc := range []struct {
		name        string
		min, rows   int
		wantSuccess bool
	}{
		{"default_threshold_control", 10000, 10000, true},
		{"higher_threshold_preserves_previous_table", 12000, 10000, false},
		{"lower_threshold_accepts_configured_feed", 2, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPR57ASNUpdateFixture(t, tc.min)
			previous, downloaded := pr57ASNTable(t, tc.min, "PREVIOUS"), pr57ASNTable(t, tc.rows, "NEXT")
			for path, body := range map[string][]byte{f.dest: previous, f.source: downloaded} {
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := f.check(t, f.dest, tc.min); err != nil {
				t.Fatalf("previous table is not usable under the collector's policy: %v\n%s", err, out)
			}
			if out, err := f.check(t, f.source, tc.min); (err == nil) != tc.wantSuccess {
				t.Fatalf("candidate fixture does not match the collector's policy: %v\n%s", err, out)
			}
			out, runErr := f.run(t, f.dir)
			if _, err := os.Stat(f.dockerLog); err != nil {
				t.Fatalf("Docker fallback was not exercised: %v\n%s", err, out)
			}
			if (runErr == nil) != tc.wantSuccess {
				t.Errorf("updater disagrees with collector at .env ASN_DB_MIN_ROWS=%d: %v\n%s", tc.min, runErr, out)
			}
			want := previous
			if tc.wantSuccess {
				want = downloaded
			}
			current, err := os.ReadFile(f.dest)
			if err != nil || !bytes.Equal(current, want) {
				t.Errorf("wrong table installed for .env ASN_DB_MIN_ROWS=%d (read error: %v)", tc.min, err)
			}
			if out, err := f.check(t, f.dest, tc.min); err != nil {
				t.Errorf("a collector restart would lose ASN enrichment: %v\n%s", err, out)
			}
		})
	}
}

// The CLI accepts a directory argument, including data (without ./). The
// Docker backend must mount the same downloaded file as the local checker.
func TestPR57ASNUpdateDockerAcceptsRelativeDirectory(t *testing.T) {
	for _, name := range []string{"absolute_control", "dot_relative_control", "bare_relative"} {
		t.Run(name, func(t *testing.T) {
			f := newPR57ASNUpdateFixture(t, 2)
			downloaded := pr57ASNTable(t, 2, "NEXT")
			if err := os.WriteFile(f.source, downloaded, 0o600); err != nil {
				t.Fatal(err)
			}
			dir := f.dir
			if name == "dot_relative_control" {
				dir = "./data"
			} else if name == "bare_relative" {
				dir = "data"
			}
			// Export the threshold explicitly to isolate the path regression.
			if out, err := f.run(t, dir, "ASN_DB_MIN_ROWS=2"); err != nil {
				t.Fatalf("valid table could not be installed using directory %q: %v\n%s", dir, err, out)
			}
			current, err := os.ReadFile(f.dest)
			if err != nil || !bytes.Equal(current, downloaded) {
				t.Fatalf("download was not installed in the requested directory: %v", err)
			}
		})
	}
}
