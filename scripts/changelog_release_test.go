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
	return f.runAt(f.root, program, args...)
}

func (f *releaseFixture) runAt(dir, program string, args ...string) (string, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir, cmd.Env = dir, f.env
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
		"tab\tname.md", "carriage\rreturn.md", "colon:name.md", ":(glob)*.md",
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

// PR #37: Git's clean status is not proof that these bytes are in HEAD.
// In particular, git rm also honors assume-unchanged and can unlink the only
// copy of a local edit after cat-file has read the older index blob.
func TestReleaseRefusesIndexHiddenLocalEdits(t *testing.T) {
	const fragment = "changes/unreleased/valuable.md"
	for _, tc := range []struct {
		flag, path string
	}{
		{"--assume-unchanged", fragment},
		{"--assume-unchanged", "CHANGELOG.md"},
		{"--skip-worktree", "CHANGELOG.md"},
		{"--skip-worktree", "VERSION"},
	} {
		t.Run(tc.flag+"/"+tc.path, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write(fragment, "- committed note\n")
			f.write("VERSION", "1.0.0\n")
			f.commit()
			f.gitOK("update-index", tc.flag, "--", tc.path)
			local := f.read(tc.path) + "\n- unique local edit absent from HEAD\n"
			f.write(tc.path, local)
			f.gitOK("diff", "--quiet", "--", "CHANGELOG.md", "VERSION", "changes")
			log, index := f.read("CHANGELOG.md"), f.gitOK("ls-files", "--stage")
			out, err := f.release("2.0.0")
			if err == nil {
				t.Errorf("release accepted an edit hidden by %s on %s:\n%s", tc.flag, tc.path, out)
			}
			f.unchanged(t, log, index)
			if data, err := os.ReadFile(filepath.Join(f.root, tc.path)); err != nil || string(data) != local {
				t.Errorf("local data lost: path=%s data=%q error=%v", tc.path, data, err)
			}
		})
	}
}

// Fail the final cat after the shell has opened/truncated its destination.
// Fragment reads still use the real cat. This models a failed output write
// without exhausting the disk and works even when tests run as root.
func (f *releaseFixture) failChangelogOutput() {
	f.t.Helper()
	bin := filepath.Join(f.scratch, "fail-write-bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		f.t.Fatal(err)
	}
	stub := "#!/bin/sh\ncase \"${2-}\" in */new) exit 73 ;; esac\nexec /bin/cat \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "cat"), []byte(stub), 0700); err != nil {
		f.t.Fatal(err)
	}
	for i, entry := range f.env {
		if strings.HasPrefix(entry, "PATH=") {
			f.env[i] = "PATH=" + bin + string(os.PathListSeparator) + strings.TrimPrefix(entry, "PATH=")
			return
		}
	}
	f.t.Fatal("fixture PATH is missing")
}

func printedReleaseRollback(out string) (string, bool) {
	const prefix = "откатить: "
	i := strings.Index(out, prefix)
	if i < 0 {
		return "", false
	}
	command := strings.TrimSpace(strings.SplitN(out[i+len(prefix):], "\n", 2)[0])
	return command, command != ""
}

func TestReleaseDoesNotWriteThroughChangelogSymlink(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("write_failure=%t", failWrite), func(t *testing.T) {
			f := newReleaseFixture(t)
			outside := filepath.Join(f.scratch, "other-project-changelog.md")
			if err := os.WriteFile(outside, []byte(legacyLog), 0600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(f.root, "CHANGELOG.md")
			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../other-project-changelog.md", logPath); err != nil {
				t.Fatal(err)
			}
			f.write("changes/unreleased/valuable.md", "- release note\n")
			f.write("VERSION", "1.0.0\n")
			f.commit()
			index := f.gitOK("ls-files", "--stage")
			if failWrite {
				f.failChangelogOutput()
			}
			out, err := f.release("2.0.0")
			if err != nil {
				if rollback, ok := printedReleaseRollback(out); ok {
					if o, e := f.run(f.bash, "--noprofile", "--norc", "-c", rollback); e != nil {
						t.Errorf("printed rollback failed: %v\n%s", e, o)
					}
				}
				if got := f.gitOK("ls-files", "--stage"); got != index {
					t.Error("refusal/rollback left the index changed")
				}
				if got := f.gitOK("status", "--porcelain"); got != "" {
					t.Errorf("refusal/rollback left a dirty tree:\n%s", got)
				}
			}
			// Git can report a clean tree while the symlink target remains lost.
			if data, err := os.ReadFile(outside); err != nil || string(data) != legacyLog {
				t.Errorf("release/rollback changed a file outside the checkout: data=%q error=%v\n%s", data, err, out)
			}
		})
	}
}

func TestReleaseRefusesUntrackedReleaseInputs(t *testing.T) {
	for _, name := range []string{"CHANGELOG.md", "VERSION"} {
		for _, ignored := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ignored=%t", name, ignored), func(t *testing.T) {
				f := newReleaseFixture(t)
				f.write("changes/unreleased/valuable.md", "- committed note\n")
				f.write("VERSION", "1.0.0\n")
				content := f.read(name)
				if err := os.Remove(filepath.Join(f.root, name)); err != nil {
					t.Fatal(err)
				}
				if ignored {
					f.write(".gitignore", "/"+name+"\n")
				}
				f.commit()
				f.write(name, content)
				log, index := f.read("CHANGELOG.md"), f.gitOK("ls-files", "--stage")
				out, err := f.release("2.0.0")
				if err == nil {
					t.Errorf("release accepted %s absent from HEAD (ignored=%t):\n%s", name, ignored, out)
				}
				f.unchanged(t, log, index)
				if got := f.read("changes/unreleased/valuable.md"); got != "- committed note\n" {
					t.Error("refusal consumed a fragment")
				}
			})
		}
	}
}

func TestReleaseRollbackWorksFromInvocationDirectory(t *testing.T) {
	for _, caller := range []string{"scripts", "outside checkout"} {
		t.Run(caller, func(t *testing.T) {
			f := newReleaseFixture(t)
			const fragment = "changes/unreleased/valuable.md"
			f.write(fragment, "- valuable note\n")
			f.write("VERSION", "1.0.0\n")
			f.commit()
			f.failChangelogOutput()
			dir := filepath.Join(f.root, "scripts")
			if caller == "outside checkout" {
				dir = f.scratch
			}
			out, err := f.runAt(dir, f.bash, "--noprofile", "--norc", filepath.Join(f.root, "scripts/changelog-release.sh"), "2.0.0", releaseDate)
			if err == nil {
				t.Fatalf("injected output failure was ignored:\n%s", out)
			}
			rollback, ok := printedReleaseRollback(out)
			if !ok {
				t.Fatalf("missing rollback command:\n%s", out)
			}
			// The script's cd cannot change the caller's current directory.
			if o, err := f.runAt(dir, f.bash, "--noprofile", "--norc", "-c", rollback); err != nil {
				t.Errorf("printed rollback failed from %s: %v\n%s", caller, err, o)
			}
			if st := f.gitOK("status", "--porcelain"); st != "" {
				t.Errorf("rollback left a dirty tree:\n%s", st)
			}
			if f.read("CHANGELOG.md") != legacyLog {
				t.Error("rollback did not restore the changelog")
			}
			if data, err := os.ReadFile(filepath.Join(f.root, fragment)); err != nil || string(data) != "- valuable note\n" {
				t.Errorf("rollback did not restore the fragment: data=%q error=%v", data, err)
			}
		})
	}
}

func TestReleaseRollbackWithoutChangesDirectory(t *testing.T) {
	f := newReleaseFixture(t)
	if err := os.RemoveAll(filepath.Join(f.root, "changes")); err != nil {
		t.Fatal(err)
	}
	f.write("VERSION", "1.0.0\n")
	f.commit()
	f.failChangelogOutput()
	out, err := f.release("2.0.0")
	if err == nil {
		t.Fatalf("injected output failure was ignored:\n%s", out)
	}
	// A preflight refusal is safe, too: no snapshot or resume is needed.
	if f.read("CHANGELOG.md") == legacyLog && f.gitOK("status", "--porcelain") == "" {
		return
	}
	rollback, ok := printedReleaseRollback(out)
	if !ok {
		t.Fatalf("missing rollback command after mutation:\n%s", out)
	}
	if o, err := f.run(f.bash, "--noprofile", "--norc", "-c", rollback); err != nil {
		t.Errorf("rollback cannot restore a changelog-only release: %v\n%s", err, o)
	}
	if st := f.gitOK("status", "--porcelain"); st != "" || f.read("CHANGELOG.md") != legacyLog {
		t.Errorf("rollback did not restore the clean initial tree:\n%s", st)
	}
}

func TestReleaseRefusesIncompleteUntrackedScan(t *testing.T) {
	for _, kind := range []string{"unreadable directory", "FIFO"} {
		t.Run(kind, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write("changes/unreleased/visible.md", "- committed visible note\n")
			f.write("VERSION", "1.0.0\n")
			f.commit()
			if kind == "FIFO" {
				mkfifo, err := exec.LookPath("mkfifo")
				if err != nil {
					t.Skip("requires POSIX mkfifo")
				}
				if out, err := f.run(mkfifo, "changes/unreleased/not-regular.md"); err != nil {
					t.Fatalf("create FIFO fixture: %v\n%s", err, out)
				}
			} else {
				f.write("changes/unreleased/locked/draft.md", "- unpublished local note\n")
				locked := filepath.Join(f.root, "changes/unreleased/locked")
				if err := os.Chmod(locked, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0700) })
				if _, err := os.ReadDir(locked); err == nil {
					t.Skip("requires an unprivileged user for the unreadable directory fixture")
				} else if !os.IsPermission(err) {
					t.Fatal(err)
				}
			}
			index := f.gitOK("ls-files", "--stage")
			out, err := f.release("2.0.0")
			if err == nil {
				t.Errorf("release accepted an incomplete untracked scan (%s):\n%s", kind, out)
			}
			f.unchanged(t, legacyLog, index)
			if data, err := os.ReadFile(filepath.Join(f.root, "changes/unreleased/visible.md")); err != nil || string(data) != "- committed visible note\n" {
				t.Errorf("visible fragment consumed despite incomplete scan: data=%q error=%v", data, err)
			}
		})
	}
}

// Git can return success after the first unlink succeeds even if a subsequent
// unlink fails. A successful release must not leave consumed fragments behind.
func TestReleaseDetectsPartialGitRemoval(t *testing.T) {
	f := newReleaseFixture(t)
	f.write("changes/unreleased/a.md", "- first note\n")
	f.write("changes/unreleased/z-locked/b.md", "- second note\n")
	f.write("VERSION", "1.0.0\n")
	f.commit()
	locked := filepath.Join(f.root, "changes/unreleased/z-locked")
	if err := os.Chmod(locked, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0700) })
	probe := filepath.Join(locked, "write-probe")
	if w, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); err == nil {
		w.Close()
		if err := os.Remove(probe); err != nil {
			t.Fatal(err)
		}
		t.Skip("requires an unprivileged user for the unwritable directory fixture")
	} else if !os.IsPermission(err) {
		t.Fatal(err)
	}
	out, err := f.release("2.0.0")
	if err == nil {
		t.Fatalf("release reported success despite a failed fragment removal:\n%s", out)
	}
	if err := os.Chmod(locked, 0700); err != nil {
		t.Fatal(err)
	}
	if rollback, ok := printedReleaseRollback(out); ok {
		if o, err := f.run(f.bash, "--noprofile", "--norc", "-c", rollback); err != nil {
			t.Fatalf("rollback after partial removal: %v\n%s", err, o)
		}
	}
	if st := f.gitOK("status", "--porcelain"); st != "" || f.read("CHANGELOG.md") != legacyLog {
		t.Errorf("refusal/rollback after partial removal did not restore the initial tree:\n%s", st)
	}
}

// Coverage controls for the index-only enumeration: gitlinks must never be read
// as blobs, and a sparse checkout must either consume all notes or roll back.
func TestReleaseRefusesGitlinks(t *testing.T) {
	for _, path := range []string{"changes", "changes/unreleased", "changes/unreleased/module"} {
		t.Run(path, func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write("VERSION", "1.0.0\n")
			f.commit()
			head := f.gitOK("rev-parse", "HEAD")
			if path != "changes/unreleased/module" {
				f.gitOK("rm", "-r", "--", path)
			}
			if err := os.MkdirAll(filepath.Join(f.root, path), 0700); err != nil {
				t.Fatal(err)
			}
			// An unpopulated gitlink, using an existing local commit; no clone.
			f.gitOK("update-index", "--add", "--cacheinfo", "160000", head, path)
			f.gitOK("commit", "-qm", "QA gitlink fixture")
			f.gitOK("diff", "--quiet", "--", "changes")
			index := f.gitOK("ls-files", "--stage")
			if out, err := f.release("2.0.0"); err == nil {
				t.Fatalf("release accepted a gitlink at %s:\n%s", path, out)
			}
			f.unchanged(t, legacyLog, index)
		})
	}
}

func TestReleaseSparseCheckoutIsCompleteOrRollsBack(t *testing.T) {
	for _, sparseIndex := range []bool{false, true} {
		t.Run(fmt.Sprintf("sparse_index=%t", sparseIndex), func(t *testing.T) {
			f := newReleaseFixture(t)
			const visible = "changes/unreleased/visible/a.md"
			const hidden = "changes/unreleased/hidden/b.md"
			f.write(visible, "- visible note\n")
			f.write(hidden, "- sparse note\n")
			f.write("VERSION", "1.0.0\n")
			f.commit()
			indexFlag := "--no-sparse-index"
			if sparseIndex {
				indexFlag = "--sparse-index"
			}
			f.gitOK("sparse-checkout", "init", "--cone", indexFlag)
			f.gitOK("sparse-checkout", "set", "scripts", "changes/unreleased/visible")
			f.absent(hidden)
			out, err := f.release("2.0.0")
			if err == nil {
				log := f.read("CHANGELOG.md")
				for _, note := range []string{"- visible note", "- sparse note"} {
					if strings.Count(log, note) != 1 {
						t.Errorf("sparse release lost or duplicated %q", note)
					}
				}
				if got := f.gitOK("ls-files", "--", visible, hidden); got != "" {
					t.Errorf("successful sparse release left fragments in the index:\n%s", got)
				}
				return
			}
			if rollback, ok := printedReleaseRollback(out); ok {
				if o, err := f.run(f.bash, "--noprofile", "--norc", "-c", rollback); err != nil {
					t.Fatalf("sparse rollback failed: %v\n%s", err, o)
				}
			}
			if st := f.gitOK("status", "--porcelain"); st != "" || f.read("CHANGELOG.md") != legacyLog {
				t.Errorf("sparse refusal/rollback left a dirty tree:\n%s", st)
			}
			f.gitOK("sparse-checkout", "disable")
			if f.read(visible) != "- visible note\n" || f.read(hidden) != "- sparse note\n" {
				t.Error("sparse refusal/rollback lost a fragment")
			}
		})
	}
}
