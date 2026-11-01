package scripts_test

// Run from the repository root in an isolated environment:
//   go test -count=1 ./scripts/changelog_release_test.go
//
// These tests execute the real script in disposable repositories. All git
// mutations, including add/commit, are confined to t.TempDir().
import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	releaseDate = "2026-11-01"
	legacyLog   = "# Changelog\n\n## Не выпущено\n\n- legacy entry\n\n## 0.9.0 — 2026-01-01\n\n- released history\n"
)

type releaseFixture struct {
	t       *testing.T
	root    string
	scratch string
	bash    string
	git     string
	env     []string
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX filenames and Bash, as used by release.yml")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	f := &releaseFixture{
		t: t, root: filepath.Join(scratch, "repo with spaces"),
		scratch: scratch, bash: bash, git: git,
	}
	for _, dir := range []string{f.root, filepath.Join(scratch, "tmp"), filepath.Join(scratch, "hooks")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Do not inherit credentials, shell startup files, Git config or pathspec flags.
	f.env = []string{
		"PATH=" + strings.Join([]string{filepath.Dir(bash), filepath.Dir(git), "/usr/bin", "/bin"}, string(os.PathListSeparator)),
		"LC_ALL=C", "TZ=UTC", "TMPDIR=" + filepath.Join(scratch, "tmp"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=QA", "GIT_AUTHOR_EMAIL=qa@example.invalid",
		"GIT_COMMITTER_NAME=QA", "GIT_COMMITTER_EMAIL=qa@example.invalid",
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the script next to this test")
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(source), "changelog-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	f.write("scripts/changelog-release.sh", string(script))
	f.write("CHANGELOG.md", legacyLog)
	f.write("changes/unreleased/README.md", "fragment format documentation\n")
	f.gitOK("init", "-q")
	f.gitOK("config", "core.hooksPath", filepath.Join(scratch, "hooks"))
	f.gitOK("config", "commit.gpgSign", "false")
	return f
}

func (f *releaseFixture) write(name, value string) {
	f.t.Helper()
	path := filepath.Join(f.root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *releaseFixture) read(name string) string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *releaseFixture) run(program string, args ...string) (string, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir, cmd.Env = f.root, f.env
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		f.t.Fatalf("command exceeded its deadline: %s", program)
	}
	return string(out), err
}

func (f *releaseFixture) gitOK(args ...string) string {
	f.t.Helper()
	out, err := f.run(f.git, args...)
	if err != nil {
		f.t.Fatalf("fixture git %q: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(out)
}

func (f *releaseFixture) commit() {
	f.t.Helper()
	f.gitOK("--literal-pathspecs", "add", "--all", "--", ".")
	f.gitOK("commit", "-qm", "QA fixture")
}

func (f *releaseFixture) release(version string) (string, error) {
	f.t.Helper()
	return f.run(f.bash, "--noprofile", "--norc", filepath.Join(f.root, "scripts/changelog-release.sh"), version, releaseDate)
}

func (f *releaseFixture) absent(name string) {
	f.t.Helper()
	if _, err := os.Lstat(filepath.Join(f.root, filepath.FromSlash(name))); !os.IsNotExist(err) {
		f.t.Errorf("%q should be absent; stat error: %v", name, err)
	}
}

// Контракт (scripts/changelog-release.sh): релиз только с чистого дерева —
// фрагменты закоммичены, всё читается из индекса, при сбое печатается команда
// отката, после неё повтор — обычная первая сборка. Регрессии ревью codex #26/#35.

func (f *releaseFixture) unchanged(t *testing.T, log string, index string) {
	t.Helper()
	if f.read("CHANGELOG.md") != log {
		t.Error("отказ изменил CHANGELOG.md")
	}
	if got := f.gitOK("ls-files", "--stage"); got != index {
		t.Error("отказ изменил индекс Git")
	}
}

func TestReleaseRefusesDirtyTree(t *testing.T) {
	for _, kind := range []string{"untracked fragment", "ignored fragment", "staged fragment edit", "modified fragment", "modified changelog", "staged version"} {
		t.Run(kind, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write("changes/unreleased/a.md", "- committed note\n")
			f.write("VERSION", "1.0.0\n")
			f.write(".gitignore", "*.ignored\n")
			f.commit()
			switch kind {
			case "untracked fragment":
				f.write("changes/unreleased/b.md", "- not committed\n")
			case "ignored fragment":
				f.write("changes/unreleased/b.ignored", "- ignored by git\n")
			case "staged fragment edit":
				f.write("changes/unreleased/a.md", "- staged\n")
				f.gitOK("add", "--", "changes/unreleased/a.md")
			case "modified fragment":
				f.write("changes/unreleased/a.md", "- worktree only\n")
			case "modified changelog":
				f.write("CHANGELOG.md", legacyLog+"\n- local edit\n")
			case "staged version":
				f.write("VERSION", "2.0.0\n")
				f.gitOK("add", "--", "VERSION")
			}
			log, index := f.read("CHANGELOG.md"), f.gitOK("ls-files", "--stage")
			out, err := f.release("2.0.0")
			if err == nil {
				t.Fatalf("release ran on a dirty tree (%s):\n%s", kind, out)
			}
			f.unchanged(t, log, index)
			if f.read("changes/unreleased/a.md") == "" {
				t.Error("fragment was consumed")
			}
		})
	}
}

func TestReleaseTreatsGitPathspecLiterally(t *testing.T) {
	for _, name := range []string{"*.md", "READM?.md", "READM[E].md", "-option.md"} {
		t.Run(name, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write("changes/unreleased/"+name, "- literal fragment\n")
			f.commit()
			out, err := f.release("2.0.0")
			if err != nil {
				t.Fatalf("release: %v\n%s", err, out)
			}
			if f.read("changes/unreleased/README.md") != "fragment format documentation\n" {
				t.Error("README was removed by a pathspec pattern")
			}
			f.absent("changes/unreleased/" + name)
			if strings.Count(f.read("CHANGELOG.md"), "- literal fragment") != 1 {
				t.Error("the literal fragment must be included exactly once")
			}
		})
	}
}

func TestReleaseRefusesSymlinks(t *testing.T) {
	for _, kind := range []string{"fragment", "changes", "changes/unreleased"} {
		t.Run(kind, func(t *testing.T) {
			f := newReleaseFixture(t)
			const secret = "ARGUS_QA_SECRET=synthetic\n"
			outside := filepath.Join(f.scratch, "operator", "unreleased")
			if err := os.MkdirAll(outside, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(outside, "private.md"), []byte(secret), 0600); err != nil {
				t.Fatal(err)
			}
			f.write(".gitignore", ".env\n")
			f.write(".env", secret)
			switch kind {
			case "fragment":
				if err := os.Symlink("../../.env", filepath.Join(f.root, "changes/unreleased/link.md")); err != nil {
					t.Fatal(err)
				}
			default:
				link := filepath.Join(f.root, filepath.FromSlash(kind))
				if err := os.RemoveAll(link); err != nil {
					t.Fatal(err)
				}
				target := outside
				if kind == "changes" {
					target = filepath.Dir(outside)
				}
				rel, err := filepath.Rel(filepath.Dir(link), target)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(rel, link); err != nil {
					t.Fatal(err)
				}
			}
			f.commit()
			log, index := f.read("CHANGELOG.md"), f.gitOK("ls-files", "--stage")
			out, err := f.release("2.0.0")
			if err == nil {
				t.Fatalf("release accepted a symlink (%s):\n%s", kind, out)
			}
			if strings.Contains(out, secret) {
				t.Error("symlink target disclosed")
			}
			f.unchanged(t, log, index)
			if data, err := os.ReadFile(filepath.Join(outside, "private.md")); err != nil || string(data) != secret {
				t.Error("file outside the checkout was touched")
			}
		})
	}
}

func TestReleaseOrderNestedHiddenAndShellNames(t *testing.T) {
	f := newReleaseFixture(t)
	names := []string{
		".hidden.md", "feature/change.md", "space name.md", "line\nbreak.md", "quote'\".md",
		"$(touch SHELL_INJECTED).md", "\x60touch BACKTICK_INJECTED\x60.md", "back\\slash.md",
	}
	sort.Strings(names)
	for i, name := range names {
		body := fmt.Sprintf("- note-%02d", i)
		if i%2 == 0 {
			body += "\n"
		}
		f.write("changes/unreleased/"+name, body)
	}
	f.commit()
	out, err := f.release("2.0.0")
	if err != nil {
		t.Fatalf("release: %v\n%s", err, out)
	}
	log := f.read("CHANGELOG.md")
	previous := strings.Index(log, "- legacy entry")
	if previous < 0 {
		t.Fatal("legacy unreleased notes were lost")
	}
	for i, name := range names {
		marker := fmt.Sprintf("- note-%02d", i)
		index := strings.Index(log, marker)
		if index <= previous || strings.Count(log, marker) != 1 {
			t.Errorf("fragment %q missing, duplicated or out of order", name)
		}
		previous = index
		f.absent("changes/unreleased/" + name)
	}
	if !strings.HasSuffix(log, "## 0.9.0 — 2026-01-01\n\n- released history\n") {
		t.Error("an existing release was changed")
	}
	if f.read("changes/unreleased/README.md") != "fragment format documentation\n" {
		t.Error("README was consumed")
	}
	f.absent("SHELL_INJECTED")
	f.absent("BACKTICK_INJECTED")
	if strings.Contains(f.gitOK("status", "--porcelain", "--", "changes"), "??") {
		t.Error("fragments must be removed from the index as well")
	}
	f.commit()
	if _, err := f.release("2.0.0"); err == nil {
		t.Error("an existing release must not be emitted again")
	}
}

func TestReleaseComparesExistingVersionLiterally(t *testing.T) {
	for _, versions := range [][2]string{{"1.0.0-alpha-1", "1.0.0-alpha.1"}, {"1.0.0+build-1", "1.0.0+build.1"}} {
		t.Run(versions[1], func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write("CHANGELOG.md", strings.ReplaceAll(legacyLog, "0.9.0", versions[0]))
			f.commit()
			if out, err := f.release(versions[1]); err != nil {
				t.Fatalf("distinct versions were mistaken for the same version: %v\n%s", err, out)
			}
			for _, v := range versions {
				if strings.Count(f.read("CHANGELOG.md"), "## "+v+" — ") != 1 {
					t.Errorf("missing or duplicate literal version %q", v)
				}
			}
		})
	}
}

func TestReleaseEmptyIsRefused(t *testing.T) {
	f := newReleaseFixture(t)
	empty := strings.Replace(legacyLog, "- legacy entry\n", "", 1)
	f.write("CHANGELOG.md", empty)
	f.commit()
	if out, err := f.release("2.0.0"); err == nil {
		t.Fatalf("empty release succeeded:\n%s", out)
	}
	if f.read("CHANGELOG.md") != empty {
		t.Error("empty release changed the changelog")
	}
}

// index.lock: git rm падает до записи CHANGELOG — ничего не изменено, повтор проходит.
func TestReleaseRetryAfterIndexLock(t *testing.T) {
	f := newReleaseFixture(t)
	f.write("changes/unreleased/change.md", "- retry marker\n")
	f.commit()
	f.write(".git/index.lock", "synthetic concurrent Git lock\n")
	if out, err := f.release("2.0.0"); err == nil {
		t.Fatalf("release ignored index.lock:\n%s", out)
	}
	if err := os.Remove(filepath.Join(f.root, ".git/index.lock")); err != nil {
		t.Fatal(err)
	}
	if f.read("CHANGELOG.md") != legacyLog {
		t.Fatal("failed git rm changed the changelog")
	}
	if out, err := f.release("2.0.0"); err != nil {
		t.Fatalf("retry: %v\n%s", err, out)
	}
	if log := f.read("CHANGELOG.md"); strings.Count(log, "## 2.0.0 — ") != 1 || strings.Count(log, "- retry marker") != 1 {
		t.Fatalf("retry must produce one release:\n%s", log)
	}
}

// Сбой после git rm (запись CHANGELOG): напечатанная команда отката возвращает
// чистое дерево, после неё повтор — обычная первая сборка без потерь.
func TestReleaseFailureAfterRemovalPrintsWorkingRollback(t *testing.T) {
	f := newReleaseFixture(t)
	f.write("changes/unreleased/valuable.md", "- valuable note\n")
	f.commit()
	logPath := filepath.Join(f.root, "CHANGELOG.md")
	if err := os.Chmod(logPath, 0400); err != nil {
		t.Fatal(err)
	}
	if w, err := os.OpenFile(logPath, os.O_WRONLY, 0); err == nil {
		w.Close()
		t.Skip("requires an unprivileged user for the read-only file fixture")
	}
	out, err := f.release("2.0.0")
	if err == nil {
		t.Fatalf("release succeeded with a read-only changelog:\n%s", out)
	}
	const prefix = "откатить: "
	i := strings.Index(out, prefix)
	if i < 0 {
		t.Fatalf("no rollback command printed:\n%s", out)
	}
	rollback := strings.TrimSpace(strings.SplitN(out[i+len(prefix):], "\n", 2)[0])
	if err := os.Chmod(logPath, 0600); err != nil {
		t.Fatal(err)
	}
	if o, err := f.run(f.bash, "--noprofile", "--norc", "-c", rollback); err != nil {
		t.Fatalf("rollback command failed: %v\n%s", err, o)
	}
	if st := f.gitOK("status", "--porcelain"); st != "" {
		t.Fatalf("rollback left a dirty tree:\n%s", st)
	}
	if o, err := f.release("2.0.0"); err != nil {
		t.Fatalf("release after rollback: %v\n%s", err, o)
	}
	if strings.Count(f.read("CHANGELOG.md"), "- valuable note") != 1 {
		t.Error("note lost or duplicated after rollback and retry")
	}
}

func TestReleaseBackslashInTempDirectory(t *testing.T) {
	f := newReleaseFixture(t)
	f.write("changes/unreleased/valuable.md", "- note under a literal temporary path\n")
	f.commit()
	tmp := filepath.Join(f.scratch, "tmp\\tab")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	for i, entry := range f.env {
		if strings.HasPrefix(entry, "TMPDIR=") {
			f.env[i] = "TMPDIR=" + tmp
		}
	}
	if out, err := f.release("2.0.0"); err != nil {
		t.Fatalf("release: %v\n%s", err, out)
	}
	log := f.read("CHANGELOG.md")
	if strings.Count(log, "- note under a literal temporary path") != 1 || strings.Count(log, "- legacy entry") != 1 {
		t.Fatalf("body lost through a temporary filename escape:\n%s", log)
	}
}
