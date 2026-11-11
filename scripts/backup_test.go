package scripts_test

// scripts/backup.sh с заглушками docker, df, stat, date и find. «Диск» общий для
// BACKUP_DIR и тома clickhouse-backups (FAKE_CAP) или, с FAKE_SEPARATE, два
// разных (FAKE_STAGING_CAP). Регрессии 11.11.2026 (argus1): полный диск,
// недописанный архив и копия на диске backups оставались после сбоя, ротация
// шла только после записи; плюс находки ревью PR #118.

import (
	"bytes"
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

// Накладные расходы оценки в backup.sh: база +10% +16 МиБ, том +1 МиБ.
func est(db int) int { return db + db/10 + 16*mb }

const fakeDocker = `#!/usr/bin/env bash
set -u
echo "docker $*" >>"$FAKE_LOG"
size() { cat "$@" 2>/dev/null | wc -c | tr -d ' '; }
used_dst() { if [ -n "${FAKE_SEPARATE:-}" ]; then size "$BACKUP_DIR"/*; else size "$BACKUP_DIR"/* "$FAKE_STAGING"/*; fi; }
used_stg() { if [ -n "${FAKE_SEPARATE:-}" ]; then size "$FAKE_STAGING"/*; else used_dst; fi; }
free_stg() { if [ -n "${FAKE_SEPARATE:-}" ]; then echo $((FAKE_STAGING_CAP - $(used_stg))); else echo $((FAKE_CAP - $(used_dst))); fi; }
case "$1 $2" in
"compose config") echo '{"name":"argus"}'; exit 0 ;;
"volume inspect") case "$*" in *device*) echo "$FAKE_STAGING" ;; *) echo /nonexistent ;; esac; exit 0 ;;
"compose cp")
  src="$FAKE_STAGING/${3##*/}"; free=$((FAKE_CAP - $(used_dst)))
  if [ -n "${FAKE_CP_FAIL:-}" ] || [ "$(size "$src")" -gt "$free" ]; then
    head -c 1000 "$src" >"$4"; echo "no space left on device" >&2; exit 1
  fi
  cp "$src" "$4"; exit 0 ;;
"run --rm")
  case "$*" in
  *" du -sk "*) echo "$(( ${FAKE_VOL_BYTES:-0} / 1024 ))	/v"; [ -n "${FAKE_DU_FAIL:-}" ] && exit 1 ;;
  *" tar "*) head -c "${FAKE_VOL_BYTES:-10}" /dev/zero ;;
  esac
  exit 0 ;;
esac
if [ "$1 $2" = "compose exec" ]; then
  args=("$@"); last="${args[$#-1]}"
  case " $* " in
  *" rm -f "*) [ -n "${FAKE_EXEC_RM_FAIL:-}" ] && { echo "OCI runtime exec failed: no space left on device" >&2; exit 1; }
               rm -f "$FAKE_STAGING/${last##*/}"; exit 0 ;;
  *" stat -c "*) size "$FAKE_STAGING/${last##*/}"; exit 0 ;;
  esac
  case "$last" in
  *system.parts*) echo "$FAKE_DB_BYTES" ;;
  *system.disks*) free_stg ;;
  *"BACKUP DATABASE"*)
    name="$(printf '%s' "$last" | sed -E "s/.*'(argus-[^']+\.zip)'.*/\1/")"
    [ -e "$FAKE_STAGING/$name" ] && { echo "BACKUP_ALREADY_EXISTS" >&2; exit 1; }
    if [ "$FAKE_ARCHIVE_BYTES" -gt "$(free_stg)" ]; then head -c 1000 /dev/zero >"$FAKE_STAGING/$name"; echo NOT_ENOUGH_SPACE >&2; exit 1; fi
    head -c "$FAKE_ARCHIVE_BYTES" /dev/zero >"$FAKE_STAGING/$name" ;;
  *) : ;;
  esac
  exit 0
fi
echo "fake docker: неизвестный вызов $*" >&2; exit 2
`

const fakeDF = `#!/usr/bin/env bash
if [ -n "${FAKE_SEPARATE:-}" ]; then used=$(cat "$BACKUP_DIR"/* 2>/dev/null | wc -c | tr -d ' ')
else used=$(cat "$BACKUP_DIR"/* "$FAKE_STAGING"/* 2>/dev/null | wc -c | tr -d ' '); fi
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "fake 0 0 $(( (FAKE_CAP - used) / 1024 )) 0% /"
`

// stat [-L] -c %d / -f %d: номер «устройства»; том на отдельном диске — с FAKE_SEPARATE.
// Ссылка без -L отвечает устройством, где лежит сама ссылка (как staging).
const fakeStat = `#!/usr/bin/env bash
deref=; for p; do [ "$p" = -L ] && deref=1; done
stg=1; [ -n "${FAKE_SEPARATE:-}" ] && stg=2
if [ -L "$p" ] && [ -z "$deref" ]; then echo "$stg"; exit 0; fi
if [ "$p" = "$FAKE_STAGING" ]; then echo "$stg"; else echo 1; fi
`

const fakeDate = `#!/usr/bin/env bash
if [ -n "${FAKE_DATE:-}" ]; then echo "$FAKE_DATE"; else exec /bin/date "$@"; fi
`

const fakeFind = `#!/usr/bin/env bash
if [ -n "${FAKE_FIND_FAIL:-}" ]; then echo "find: сбой" >&2; exit 1; fi
for d in /usr/bin /bin; do [ -x "$d/find" ] && exec "$d/find" "$@"; done
exit 127
`

type backupEnv struct {
	root, bin, dir, staging, log string
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
	// Копия в свой корень: скрипт делает cd в родителя scripts/ и читает .env оттуда.
	e.write(t, filepath.Join(e.root, "scripts", "backup.sh"), string(src), 0o755)
	for name, body := range map[string]string{"docker": fakeDocker, "df": fakeDF, "stat": fakeStat,
		"date": fakeDate, "find": fakeFind, "logger": "#!/bin/sh\nexit 0\n"} {
		e.write(t, filepath.Join(e.bin, name), body, 0o755)
	}
	e.write(t, filepath.Join(e.root, ".env"), "CLICKHOUSE_PASSWORD=x\n"+dotenv, 0o600)
	return e
}

func (e *backupEnv) write(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// Полный набор старого формата (четыре файла, без признака) или только zip.
func (e *backupEnv) set(t *testing.T, stamp string, size int, complete bool) {
	t.Helper()
	base := filepath.Join(e.dir, "argus-"+stamp)
	e.write(t, base+".zip", string(make([]byte, size)), 0o600)
	if complete {
		e.write(t, base+"-web-auth.tar.gz.enc", "a", 0o600)
		e.write(t, base+"-shipper-state.tar.gz", "s", 0o600)
		e.write(t, base+"-collector-state.tar.gz.enc", "c", 0o600)
	}
}

func (e *backupEnv) age(t *testing.T, stamp string, d time.Duration) {
	t.Helper()
	old := time.Now().Add(-d)
	matches, _ := filepath.Glob(filepath.Join(e.dir, "argus-"+stamp+"*"))
	for _, m := range matches {
		if err := os.Chtimes(m, old, old); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *backupEnv) run(t *testing.T, capBytes, dbBytes, archiveBytes int, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, x := range ents {
		if !strings.HasPrefix(x.Name(), ".") {
			n = append(n, x.Name())
		}
	}
	return n
}

func (e *backupEnv) exists(name string) bool {
	_, err := os.Stat(filepath.Join(e.dir, name))
	return err == nil
}

// Файлы, которых не было среди заранее созданных наборов.
func (e *backupEnv) fresh(t *testing.T, old ...string) []string {
	var out []string
next:
	for _, n := range names(t, e.dir) {
		for _, o := range old {
			if strings.HasPrefix(n, "argus-"+o) {
				continue next
			}
		}
		out = append(out, n)
	}
	return out
}

func (e *backupEnv) dockerLog(t *testing.T) string {
	b, _ := os.ReadFile(e.log)
	return string(b)
}

func wantFullNewSet(t *testing.T, files []string, out string) {
	t.Helper()
	want := []string{".zip", ".complete", "-web-auth.tar.gz.enc", "-shipper-state.tar.gz", "-collector-state.tar.gz.enc"}
	if len(files) != len(want) {
		t.Fatalf("новый набор: %v\n%s", files, out)
	}
	for _, w := range want {
		found := false
		for _, f := range files {
			found = found || strings.HasSuffix(f, w)
		}
		if !found {
			t.Fatalf("в новом наборе нет *%s: %v\n%s", w, files, out)
		}
	}
}

func TestBackupSuccess(t *testing.T) {
	e := newBackupEnv(t, "")
	out, err := e.run(t, 200*mb, 2*mb, 2*mb)
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	wantFullNewSet(t, e.fresh(t), out)
	if s := names(t, e.staging); len(s) != 0 {
		t.Fatalf("копия на диске backups осталась: %v", s)
	}
}

// 11.11.2026: cp упал на полном диске, `docker compose exec rm` тоже
// (runc не пишет во /tmp) — недописанный zip и копия на диске backups остались.
func TestBackupCopyFailureRemovesPartialAndStaging(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261110T030001Z", 3*mb, true)
	out, err := e.run(t, 200*mb, 2*mb, 2*mb, "FAKE_CP_FAIL=1", "FAKE_EXEC_RM_FAIL=1")
	if err == nil {
		t.Fatalf("сбой cp должен давать ненулевой код\n%s", out)
	}
	if n := e.fresh(t, "20261110T030001Z"); len(n) != 0 {
		t.Fatalf("файлы этого запуска остались: %v\n%s", n, out)
	}
	if s := names(t, e.staging); len(s) != 0 {
		t.Fatalf("копия на диске backups осталась при неработающем exec: %v\n%s", s, out)
	}
	if !e.exists("argus-20261110T030001Z.zip") {
		t.Fatalf("прежний набор пострадал\n%s", out)
	}
}

func TestBackupPrunesOldestCompleteToFit(t *testing.T) {
	e := newBackupEnv(t, "")
	old := []string{"20261108T030001Z", "20261109T030001Z", "20261110T030001Z"}
	for _, s := range old {
		e.set(t, s, 20*mb, true)
	}
	need := 2*est(2*mb) + 3*mb + mb // пик на одном диске + тома + резерв
	out, err := e.run(t, 60*mb+need-10*mb, 2*mb, 2*mb)
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if e.exists("argus-"+old[0]+".zip") || e.exists("argus-"+old[0]+"-web-auth.tar.gz.enc") {
		t.Fatalf("старейший набор должен быть удалён целиком\n%s", out)
	}
	for _, s := range old[1:] {
		if !e.exists("argus-" + s + ".zip") {
			t.Fatalf("лишнее удаление %s\n%s", s, out)
		}
	}
	wantFullNewSet(t, e.fresh(t, old...), out)
}

func TestBackupRefusesWithoutDroppingLastCompleteSet(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261110T030001Z", 30*mb, true)
	out, err := e.run(t, 40*mb, 2*mb, 2*mb)
	if err == nil {
		t.Fatalf("при нехватке места нужен отказ\n%s", out)
	}
	if !e.exists("argus-20261110T030001Z.zip") {
		t.Fatalf("последний полный набор удалён\n%s", out)
	}
	if strings.Contains(e.dockerLog(t), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен при нехватке места:\n%s", e.dockerLog(t))
	}
	if !strings.Contains(out, "удалять больше нечего") {
		t.Fatalf("нет понятной причины отказа:\n%s", out)
	}
}

// Ревью #118 P1: недописанный zip новее последнего полного набора не делает тот
// «лишним» — удаляется мусор, полный остаётся.
func TestBackupPartialNewerZipIsNotCompleteSet(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261110T030001Z", 30*mb, true)
	e.set(t, "20261111T030001Z", 30*mb, false) // как после сбоя 11.11
	out, err := e.run(t, 70*mb, 2*mb, 2*mb)
	if err == nil {
		t.Fatalf("места не хватает и после удаления мусора — нужен отказ\n%s", out)
	}
	if e.exists("argus-20261111T030001Z.zip") {
		t.Fatalf("недописанный набор должен уйти первым\n%s", out)
	}
	if !e.exists("argus-20261110T030001Z.zip") || !e.exists("argus-20261110T030001Z-collector-state.tar.gz.enc") {
		t.Fatalf("последний полный набор удалён ради места\n%s", out)
	}
}

// Ревью #118 P1: повторный запуск в ту же секунду не трогает чужой набор.
func TestBackupSameSecondRunKeepsExistingSet(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261111T030001Z", mb, true)
	e.write(t, filepath.Join(e.staging, "argus-20261111T030001Z.zip"), "staging", 0o600)
	before := names(t, e.dir)
	out, err := e.run(t, 200*mb, 2*mb, 2*mb, "FAKE_DATE=20261111T030001Z")
	if err == nil {
		t.Fatalf("коллизия имени должна давать отказ\n%s", out)
	}
	if got := names(t, e.dir); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Fatalf("файлы набора изменились: %v → %v\n%s", before, got, out)
	}
	if b, _ := os.ReadFile(filepath.Join(e.staging, "argus-20261111T030001Z.zip")); string(b) != "staging" {
		t.Fatalf("чужая копия на диске backups удалена\n%s", out)
	}
	if strings.Contains(e.dockerLog(t), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен при коллизии имени")
	}
}

// Ревью #118 P1: сбой после записи всех файлов (ротация) не откатывает набор.
func TestBackupRotationFailureKeepsNewSet(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261101T030001Z", mb, true)
	out, err := e.run(t, 200*mb, 2*mb, 2*mb, "FAKE_FIND_FAIL=1")
	if err != nil {
		t.Fatalf("сбой ротации не должен ронять готовый бэкап: %v\n%s", err, out)
	}
	wantFullNewSet(t, e.fresh(t, "20261101T030001Z"), out)
}

func TestBackupRotationByAgeKeepsRecent(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261020T030001Z", mb, true)
	e.set(t, "20261110T030001Z", mb, true)
	e.age(t, "20261020T030001Z", 30*24*time.Hour)
	e.age(t, "20261110T030001Z", 12*time.Hour)
	out, err := e.run(t, 200*mb, 2*mb, 2*mb, "BACKUP_KEEP_DAYS=2")
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if e.exists("argus-20261020T030001Z.zip") || e.exists("argus-20261020T030001Z-shipper-state.tar.gz") {
		t.Fatalf("старый набор не удалён ротацией\n%s", out)
	}
	if !e.exists("argus-20261110T030001Z.zip") {
		t.Fatalf("свежий набор удалён ротацией\n%s", out)
	}
}

// Ревью #118 P1: большой архив тома проверяется до записи.
func TestBackupVolumeTooLargeRefusedBeforeWrite(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261110T030001Z", mb, true)
	out, err := e.run(t, 80*mb, 2*mb, 2*mb, "FAKE_VOL_BYTES="+strconv.Itoa(30*mb))
	if err == nil {
		t.Fatalf("том не влезает — нужен отказ\n%s", out)
	}
	if n := e.fresh(t, "20261110T030001Z"); len(n) != 0 {
		t.Fatalf("файлы этого запуска остались: %v\n%s", n, out)
	}
	if strings.Contains(e.dockerLog(t), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен, хотя тома не влезают")
	}
}

// Ревью #118 P2: staging на отдельном диске — наборы в BACKUP_DIR не удаляются зря.
func TestBackupSeparateStagingDiskDoesNotPruneDestination(t *testing.T) {
	e := newBackupEnv(t, "")
	old := []string{"20261109T030001Z", "20261110T030001Z"}
	for _, s := range old {
		e.set(t, s, mb, true)
	}
	out, err := e.run(t, 500*mb, 2*mb, 2*mb, "FAKE_SEPARATE=1", "FAKE_STAGING_CAP="+strconv.Itoa(10*mb))
	if err == nil {
		t.Fatalf("staging переполнен — нужен отказ\n%s", out)
	}
	for _, s := range old {
		if !e.exists("argus-" + s + ".zip") {
			t.Fatalf("набор %s удалён, хотя он на другом диске\n%s", s, out)
		}
	}
	if !strings.Contains(out, "на другом диске") {
		t.Fatalf("нет понятной причины отказа:\n%s", out)
	}
}

// Ревью #118 P2: файлы с чужими именами (в т.ч. с переводом строки) не удаляются.
func TestBackupNeverDeletesForeignFiles(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261108T030001Z", 20*mb, true)
	e.set(t, "20261110T030001Z", 20*mb, true)
	for _, f := range []string{"argus-z\n0foreign.zip", "0foreign.zip", "0foreign-note", "argus-notes.txt"} {
		e.write(t, filepath.Join(e.dir, f), "keep", 0o600)
	}
	e.age(t, "", 0)
	need := 2*est(2*mb) + 3*mb + mb
	out, err := e.run(t, 40*mb+need-5*mb, 2*mb, 2*mb, "BACKUP_KEEP_DAYS=1")
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	for _, f := range []string{"argus-z\n0foreign.zip", "0foreign.zip", "0foreign-note", "argus-notes.txt"} {
		if !e.exists(f) {
			t.Fatalf("чужой файл %q удалён\n%s", f, out)
		}
	}
}

// Ревью #118 P1 (mawk): свободное место в сотни ГиБ не превращается в 1e+11.
func TestBackupHugeDiskParsedExactly(t *testing.T) {
	e := newBackupEnv(t, "")
	out, err := e.run(t, 300<<30, 2*mb, 2*mb)
	if err != nil {
		t.Fatalf("backup на диске 300 ГиБ: %v\n%s", err, out)
	}
	wantFullNewSet(t, e.fresh(t), out)
}

// Ревью #118 P2: пустая база, архив ненулевой, свободно ровно резерв — BACKUP не запускается.
func TestBackupZeroEstimateStillNeedsHeadroom(t *testing.T) {
	e := newBackupEnv(t, "")
	out, err := e.run(t, mb, 0, mb/2)
	if err == nil {
		t.Fatalf("нужен отказ\n%s", out)
	}
	if strings.Contains(e.dockerLog(t), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен без запаса на метаданные")
	}
}

func TestBackupEnvAndNumbers(t *testing.T) {
	e := newBackupEnv(t, "BACKUP_KEEP_DAYS=14\n")
	out, err := e.run(t, 200*mb, mb, mb, "BACKUP_KEEP_DAYS=2")
	if err != nil || !strings.Contains(out, "старше 2 дней") {
		t.Fatalf("BACKUP_KEEP_DAYS из окружения не победил .env: %v\n%s", err, out)
	}
	out, err = e.run(t, 200*mb, mb, mb, "BACKUP_KEEP_DAYS=08", "FAKE_DATE=20261111T040000Z")
	if err != nil || !strings.Contains(out, "старше 8 дней") {
		t.Fatalf("08 — десятичное 8, не восьмеричная ошибка: %v\n%s", err, out)
	}
	for _, bad := range []string{"BACKUP_KEEP_DAYS=7d", "BACKUP_KEEP_DAYS=0", "BACKUP_RESERVE_MB=18446744073709551616", "BACKUP_RESERVE_MB=-1"} {
		os.Remove(e.log)
		out, err = e.run(t, 200*mb, mb, mb, bad)
		if err == nil || !strings.Contains(out, "нужно целое число") {
			t.Fatalf("%s должен отклоняться:\n%s", bad, out)
		}
		if bytes.Contains([]byte(e.dockerLog(t)), []byte("compose")) {
			t.Fatalf("%s: docker вызван до проверки чисел", bad)
		}
	}
}

// Ревью #118 r2 P1: оборванный запуск оставляет *.part даже со всеми четырьмя
// файлами — это не полный набор, удаляется первым, исправный остаётся.
func TestBackupKilledRunWithFourPartFilesIsNotComplete(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261110T030001Z", 30*mb, true)
	b := filepath.Join(e.dir, "argus-20261111T030001Z")
	for _, x := range []string{".zip.part", "-web-auth.tar.gz.enc.part", "-shipper-state.tar.gz.part", "-collector-state.tar.gz.enc.part"} {
		e.write(t, b+x, string(make([]byte, 2*mb)), 0o600)
	}
	// Нужно 2·est + тома 3 МиБ + резерв ≈ 40,4 МиБ; после удаления мусора свободно 40.
	out, err := e.run(t, 70*mb, 2*mb, 2*mb)
	if err == nil {
		t.Fatalf("места не хватает и после удаления мусора — нужен отказ\n%s", out)
	}
	if left, _ := filepath.Glob(b + "*"); len(left) != 0 {
		t.Fatalf("оборванный набор не удалён целиком: %v\n%s", left, out)
	}
	if !e.exists("argus-20261110T030001Z.zip") || !e.exists("argus-20261110T030001Z-collector-state.tar.gz.enc") {
		t.Fatalf("исправный набор удалён ради места\n%s", out)
	}
}

func TestBackupLeavesNoPartFiles(t *testing.T) {
	e := newBackupEnv(t, "")
	out, err := e.run(t, 200*mb, 2*mb, 2*mb)
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if p, _ := filepath.Glob(filepath.Join(e.dir, "*.part")); len(p) != 0 {
		t.Fatalf("остались *.part: %v", p)
	}
}

// Ревью #118 r2 P2: BACKUP_DIR — ссылка на другой диск; staging на корне полон.
func TestBackupSymlinkedDirOnOtherDiskChecksStaging(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261109T030001Z", mb, true)
	e.set(t, "20261110T030001Z", mb, true)
	link := filepath.Join(e.root, "link")
	if err := os.Symlink(e.dir, link); err != nil {
		t.Fatal(err)
	}
	out, err := e.run(t, 500*mb, 2*mb, 2*mb, "BACKUP_DIR="+link, "FAKE_SEPARATE=1",
		"FAKE_STAGING_CAP="+strconv.Itoa(10*mb))
	if err == nil {
		t.Fatalf("staging переполнен — нужен отказ\n%s", out)
	}
	if strings.Contains(e.dockerLog(t), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен: ссылка принята за тот же диск\n%s", out)
	}
	for _, s := range []string{"20261109T030001Z", "20261110T030001Z"} {
		if !e.exists("argus-" + s + ".zip") {
			t.Fatalf("набор %s удалён\n%s", s, out)
		}
	}
}

// Ревью #118 r2 P2: du с ошибкой и частичным числом — отказ до удаления и BACKUP.
func TestBackupVolumeEstimateFailureStopsEarly(t *testing.T) {
	e := newBackupEnv(t, "")
	e.set(t, "20261109T030001Z", 20*mb, true)
	e.set(t, "20261110T030001Z", 20*mb, true)
	out, err := e.run(t, 60*mb, 2*mb, 2*mb, "FAKE_DU_FAIL=1", "FAKE_VOL_BYTES=131072")
	if err == nil {
		t.Fatalf("ошибка du должна давать отказ\n%s", out)
	}
	if strings.Contains(e.dockerLog(t), "BACKUP DATABASE") {
		t.Fatalf("BACKUP запущен при ошибке оценки тома")
	}
	for _, s := range []string{"20261109T030001Z", "20261110T030001Z"} {
		if !e.exists("argus-" + s + ".zip") {
			t.Fatalf("набор %s удалён при ошибке оценки\n%s", s, out)
		}
	}
}
