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

func TestReleaseTreatsGitPathspecLiterally(t *testing.T) {
	for _, name := range []string{"*.md", "READM?.md", "READM[E].md"} {
		for _, tracked := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/tracked=%t", name, tracked), func(t *testing.T) {
				f := newReleaseFixture(t)
				fragment := "changes/unreleased/" + name
				if tracked {
					f.write(fragment, "- literal fragment\n")
				}
				f.commit()
				if !tracked {
					f.write(fragment, "- literal fragment\n")
				}
				// This excluded file must survive, including changes not in Git.
				const readme = "uncommitted documentation which must not be removed\n"
				f.write("changes/unreleased/README.md", readme)
				out, err := f.release("2.0.0")
				if err != nil {
					t.Fatalf("release failed for a literal filename: %v\n%s", err, out)
				}
				got, readErr := os.ReadFile(filepath.Join(f.root, "changes/unreleased/README.md"))
				if readErr != nil || string(got) != readme {
					t.Errorf("git pathspec %q destroyed excluded README changes: %v; got %q", name, readErr, got)
				}
				f.absent(fragment)
				if strings.Count(f.read("CHANGELOG.md"), "- literal fragment") != 1 {
					t.Error("the literal fragment must be included exactly once")
				}
			})
		}
	}
}

func TestReleaseDoesNotPublishSymlinkTargets(t *testing.T) {
	f := newReleaseFixture(t)
	const dummy = "ARGUS_QA_SECRET=synthetic-marker-not-a-real-secret\n"
	f.write(".gitignore", ".env\n")
	f.write(".env", dummy)
	if err := os.Symlink("../../.env", filepath.Join(f.root, "changes/unreleased/link.md")); err != nil {
		t.Fatal(err)
	}
	f.commit()
	out, _ := f.release("2.0.0")
	if strings.Contains(f.read("CHANGELOG.md"), dummy) || strings.Contains(out, dummy) {
		t.Error("a fragment symlink copied an ignored operator file into published release data")
	}
	if f.read(".env") != dummy {
		t.Error("the symlink target was modified")
	}
}

func TestReleaseCanRetryAfterGitIndexLock(t *testing.T) {
	f := newReleaseFixture(t)
	f.write("changes/unreleased/change.md", "- retry marker\n")
	f.commit()
	f.write(".git/index.lock", "synthetic concurrent Git lock\n")
	firstOut, firstErr := f.release("2.0.0")
	if err := os.Remove(filepath.Join(f.root, ".git/index.lock")); err != nil {
		t.Fatal(err)
	}
	if firstErr != nil {
		out, err := f.release("2.0.0")
		if err != nil {
			t.Fatalf("release cannot recover after the lock is removed\nfirst: %v\n%s\nretry: %v\n%s", firstErr, firstOut, err, out)
		}
	}
	f.absent("changes/unreleased/change.md")
	log := f.read("CHANGELOG.md")
	if strings.Count(log, "## 2.0.0 — ") != 1 || strings.Count(log, "- retry marker") != 1 {
		t.Fatalf("retry must produce one complete release, got:\n%s", log)
	}
}

func TestReleaseDoesNotSucceedWithUnconsumedFragments(t *testing.T) {
	for _, name := range []string{".hidden.md", "feature/change.md"} {
		t.Run(name, func(t *testing.T) {
			f := newReleaseFixture(t)
			fragment := "changes/unreleased/" + name
			f.write(fragment, "- otherwise lost release note\n")
			f.commit()
			out, err := f.release("2.0.0")
			if err != nil {
				// Rejecting unsupported paths before changing anything is also safe.
				if f.read("CHANGELOG.md") != legacyLog || f.read(fragment) != "- otherwise lost release note\n" {
					t.Fatalf("rejected fragment left a partial release:\n%s", out)
				}
				return
			}
			f.absent(fragment)
			if strings.Count(f.read("CHANGELOG.md"), "- otherwise lost release note") != 1 {
				t.Error("script reported success but omitted a fragment that release.yml will block on")
			}
		})
	}
}

func TestReleaseComparesExistingVersionLiterally(t *testing.T) {
	for _, versions := range [][2]string{
		{"1.0.0-alpha-1", "1.0.0-alpha.1"},
		{"1.0.0+build-1", "1.0.0+build.1"},
	} {
		t.Run(versions[1], func(t *testing.T) {
			f := newReleaseFixture(t)
			f.write("CHANGELOG.md", strings.ReplaceAll(legacyLog, "0.9.0", versions[0]))
			out, err := f.release(versions[1])
			if err != nil {
				t.Fatalf("distinct valid versions were mistaken for the same version: %v\n%s", err, out)
			}
			log := f.read("CHANGELOG.md")
			for _, version := range versions {
				if strings.Count(log, "## "+version+" — ") != 1 {
					t.Errorf("missing or duplicate literal version %q", version)
				}
			}
		})
	}
}

func TestReleasePreservesOrderAndLiteralShellNames(t *testing.T) {
	for _, tracked := range []bool{true, false} {
		t.Run(fmt.Sprintf("tracked=%t", tracked), func(t *testing.T) {
			f := newReleaseFixture(t)
			names := []string{
				"space name.md", "line\nbreak.md", "quote'\".md", "-option.md",
				"$(touch SHELL_INJECTED).md", "\x60touch BACKTICK_INJECTED\x60.md",
				"back\\slash.md",
			}
			sort.Strings(names) // LC_ALL=C in the child process.
			if !tracked {
				f.commit()
			}
			for i, name := range names {
				// Deliberately omit the last newline from alternating fragments.
				body := fmt.Sprintf("- note-%02d", i)
				if i%2 == 0 {
					body += "\n"
				}
				f.write("changes/unreleased/"+name, body)
			}
			if tracked {
				f.commit()
			}
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
			if _, err := f.release("2.0.0"); err == nil {
				t.Error("an existing release must not be emitted again")
			}
			if f.read("CHANGELOG.md") != log {
				t.Error("rerunning an already completed release changed the changelog")
			}
		})
	}
}

func TestReleaseEmptyInputAndReadFailureLeaveChangelogUntouched(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		f := newReleaseFixture(t)
		empty := strings.Replace(legacyLog, "- legacy entry\n", "", 1)
		f.write("CHANGELOG.md", empty)
		if out, err := f.release("2.0.0"); err == nil {
			t.Fatalf("empty release unexpectedly succeeded:\n%s", out)
		}
		if f.read("CHANGELOG.md") != empty {
			t.Error("an empty release changed the changelog")
		}
	})
	t.Run("read failure", func(t *testing.T) {
		f := newReleaseFixture(t)
		f.write("changes/unreleased/good.md", "- must be retained\n")
		if err := os.Mkdir(filepath.Join(f.root, "changes/unreleased/not-a-file.md"), 0700); err != nil {
			t.Fatal(err)
		}
		if out, err := f.release("2.0.0"); err == nil {
			t.Fatalf("fragment read failure was ignored:\n%s", out)
		}
		if f.read("CHANGELOG.md") != legacyLog || f.read("changes/unreleased/good.md") != "- must be retained\n" {
			t.Error("failed pipeline changed the changelog or consumed a fragment")
		}
		f.absent("CHANGELOG.md.new")
		entries, err := os.ReadDir(filepath.Join(f.scratch, "tmp"))
		if err != nil || len(entries) != 0 {
			t.Errorf("temporary body was not cleaned up: entries=%v error=%v", entries, err)
		}
	})
}
