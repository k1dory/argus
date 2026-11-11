package scripts_test

// scripts/backup.sh с заглушками docker и df: один общий «диск» ёмкостью
// FAKE_CAP байт на каталог бэкапов и том clickhouse-backups. Регрессии
// 11.11.2026 (argus1): полный диск, недописанный архив и копия на диске
// backups ClickHouse оставались после сбоя, а ротация шла только после записи.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const mb = 1 << 20

const fakeDocker = `#!/usr/bin/env bash
set -u
echo "docker $*" >>"$FAKE_LOG"
used() { cat "$BACKUP_DIR"/* "$FAKE_STAGING"/* 2>/dev/null | wc -c | tr -d ' '; }
case "$1 $2" in
"compose config") echo '{"name":"argus"}'; exit 0 ;;
"volume inspect") echo "$FAKE_STAGING"; exit 0 ;;
"compose cp")
  src="$FAKE_STAGING/${3##*/}"
  if [ -n "${FAKE_CP_FAIL:-}" ]; then head -c 1000 "$src" >"$4"; echo "no space left on device" >&2; exit 1; fi
  cp "$src" "$4"; exit 0 ;;
"run --rm") echo "tar of $4"; exit 0 ;;
esac
if [ "$1 $2" = "compose exec" ]; then
  args=("$@"); last="${args[$#-1]}"
  case " $* " in
  *" rm -f "*) [ -n "${FAKE_EXEC_RM_FAIL:-}" ] && { echo "OCI runtime exec failed: no space left on device" >&2; exit 1; }
               rm -f "$FAKE_STAGING/${last##*/}"; exit 0 ;;
  *" stat -c "*) wc -c <"$FAKE_STAGING/${last##*/}" | tr -d ' '; exit 0 ;;
  esac
  case "$last" in
  *system.parts*) echo "$FAKE_DB_BYTES" ;;
  *system.disks*) echo $((FAKE_CAP - $(used))) ;;
  *"BACKUP DATABASE"*)
    name="$(printf '%s' "$last" | sed -E "s/.*'(argus-[^']+\.zip)'.*/\1/")"
    head -c "$FAKE_ARCHIVE_BYTES" /dev/zero >"$FAKE_STAGING/$name" ;;
  *) : ;;
  esac
  exit 0
fi
echo "fake docker: неизвестный вызов $*" >&2; exit 2
`

const fakeDF = `#!/usr/bin/env bash
used=$(cat "$BACKUP_DIR"/* "$FAKE_STAGING"/* 2>/dev/null | wc -c | tr -d ' ')
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "fake 0 0 $(( (FAKE_CAP - used) / 1024 )) 0% /"
`

type backupEnv struct {
	root, bin, dir, staging, log string
	extra                        []string
}

func newBackupEnv(t *testing.T, dotenv string) *backupEnv {
	t.Helper()
	e := &backupEnv{root: t.TempDir()}
	e.bin = filepath.Join(e.root, "bin")
	e.dir = filepath.Join(e.root, "backups")
	e.staging = filepath.Join(e.root, "staging")
	e.log = filepath.Join(e.root, "docker.log")
	for _, d := range []string{e.bin, e.dir, e.staging, filepath.Join(e.root, "scripts")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src, err := os.ReadFile("backup.sh")
	if err != nil {
		t.Fatal(err)
	}
	write := func(p, body string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	// Копия в свой корень: скрипт делает cd в родителя scripts/ и читает .env оттуда.
	write(filepath.Join(e.root, "scripts", "backup.sh"), string(src), 0o755)
	write(filepath.Join(e.bin, "docker"), fakeDocker, 0o755)
	write(filepath.Join(e.bin, "df"), fakeDF, 0o755)
	write(filepath.Join(e.bin, "logger"), "#!/bin/sh\nexit 0\n", 0o755)
	write(filepath.Join(e.root, ".env"), "CLICKHOUSE_PASSWORD=x\n"+dotenv, 0o600)
	return e
}

func (e *backupEnv) oldSet(t *testing.T, stamp string, size int) {
	t.Helper()
	base := filepath.Join(e.dir, "argus-"+stamp)
	if err := os.WriteFile(base+".zip", make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+"-web-auth.tar.gz.enc", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *backupEnv) run(t *testing.T, capBytes, dbBytes, archiveBytes int, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(e.root, "scripts", "backup.sh"))
	cmd.Env = append([]string{
		"PATH=" + e.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + e.root, "TMPDIR=" + t.TempDir(), "LC_ALL=C",
		"BACKUP_DIR=" + e.dir, "BACKUP_KEY=test-key", "BACKUP_RESERVE_MB=1",
		"FAKE_STAGING=" + e.staging, "FAKE_LOG=" + e.log,
		"FAKE_CAP=" + strconv.Itoa(capBytes),
		"FAKE_DB_BYTES=" + strconv.Itoa(dbBytes),
		"FAKE_ARCHIVE_BYTES=" + strconv.Itoa(archiveBytes),
	}, env...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *backupEnv) names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, x := range ents {
		n = append(n, x.Name())
	}
	return n
}

// Наборы текущего запуска: всё, что не из заранее созданных.
func newFiles(names []string, old ...string) []string {
	var out []string
next:
	for _, n := range names {
		for _, o := range old {
			if strings.HasPrefix(n, "argus-"+o) {
				continue next
			}
		}
		out = append(out, n)
	}
	return out
}

func TestBackupSuccess(t *testing.T) {
	e := newBackupEnv(t, "")
	out, err := e.run(t, 100*mb, 2*mb, 2*mb)
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	got := e.names(t, e.dir)
	var zip, auth, shipper, collector bool
	for _, n := range got {
		zip = zip || strings.HasSuffix(n, "Z.zip")
		auth = auth || strings.HasSuffix(n, "-web-auth.tar.gz.enc")
		shipper = shipper || strings.HasSuffix(n, "-shipper-state.tar.gz")
		collector = collector || strings.HasSuffix(n, "-collector-state.tar.gz.enc")
	}
	if !zip || !auth || !shipper || !collector {
		t.Fatalf("неполный набор: %v\n%s", got, out)
	}
	if s := e.names(t, e.staging); len(s) != 0 {
		t.Fatalf("копия на диске backups осталась: %v", s)
	}
}

// 11.11.2026: cp упал на полном диске, `docker compose exec rm` тоже
// (runc не пишет во /tmp) — 15 ГБ недописанного zip и 19 ГБ копии остались.
func TestBackupCopyFailureRemovesPartialAndStaging(t *testing.T) {
	e := newBackupEnv(t, "")
	e.oldSet(t, "20261110T030001Z", 3*mb)
	out, err := e.run(t, 100*mb, 2*mb, 2*mb, "FAKE_CP_FAIL=1", "FAKE_EXEC_RM_FAIL=1")
	if err == nil {
		t.Fatalf("сбой cp должен давать ненулевой код\n%s", out)
	}
	if n := newFiles(e.names(t, e.dir), "20261110T030001Z"); len(n) != 0 {
		t.Fatalf("недописанные файлы остались: %v\n%s", n, out)
	}
	if s := e.names(t, e.staging); len(s) != 0 {
		t.Fatalf("копия на диске backups осталась при неработающем exec: %v\n%s", s, out)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "argus-20261110T030001Z.zip")); err != nil {
		t.Fatalf("прежний набор пострадал: %v", err)
	}
}

func TestBackupPrunesOldestToFit(t *testing.T) {
	e := newBackupEnv(t, "")
	old := []string{"20261108T030001Z", "20261109T030001Z", "20261110T030001Z"}
	for _, s := range old {
		e.oldSet(t, s, 3*mb)
	}
	// Занято 9 МБ из 13: до BACKUP свободно 4 ≥ 2+1, после — 2 < 2+1 → уходит один старый набор.
	out, err := e.run(t, 13*mb, 2*mb, 2*mb)
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "argus-"+old[0]+".zip")); !os.IsNotExist(err) {
		t.Fatalf("самый старый набор должен быть удалён\n%s", out)
	}
	for _, f := range []string{"argus-" + old[0] + "-web-auth.tar.gz.enc"} {
		if _, err := os.Stat(filepath.Join(e.dir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s: набор удалён не целиком", f)
		}
	}
	for _, s := range old[1:] {
		if _, err := os.Stat(filepath.Join(e.dir, "argus-"+s+".zip")); err != nil {
			t.Fatalf("лишнее удаление %s\n%s", s, out)
		}
	}
	if len(newFiles(e.names(t, e.dir), old...)) != 4 {
		t.Fatalf("новый набор неполон: %v\n%s", e.names(t, e.dir), out)
	}
}

func TestBackupRefusesWithoutDroppingLastSet(t *testing.T) {
	e := newBackupEnv(t, "")
	e.oldSet(t, "20261110T030001Z", 3*mb)
	// Свободно 2 МБ < 2+1, а единственный прежний набор удалять нельзя.
	out, err := e.run(t, 5*mb, 2*mb, 2*mb)
	if err == nil {
		t.Fatalf("при нехватке места нужен отказ\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "argus-20261110T030001Z.zip")); err != nil {
		t.Fatalf("последний набор удалён: %v\n%s", err, out)
	}
	log, _ := os.ReadFile(e.log)
	if strings.Contains(string(log), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен при нехватке места:\n%s", log)
	}
	if !strings.Contains(out, "удалять больше нечего") {
		t.Fatalf("нет понятной причины отказа:\n%s", out)
	}
}

func TestBackupEnvOverridesDotEnv(t *testing.T) {
	e := newBackupEnv(t, "BACKUP_KEEP_DAYS=14\n")
	out, err := e.run(t, 100*mb, mb, mb, "BACKUP_KEEP_DAYS=2")
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if !strings.Contains(out, "старше 2 дней") {
		t.Fatalf("BACKUP_KEEP_DAYS из окружения не победил .env:\n%s", out)
	}
	out, err = e.run(t, 100*mb, mb, mb, "BACKUP_KEEP_DAYS=7d")
	if err == nil || !strings.Contains(out, "целое число") {
		t.Fatalf("нечисловой BACKUP_KEEP_DAYS должен отклоняться:\n%s", out)
	}
}
