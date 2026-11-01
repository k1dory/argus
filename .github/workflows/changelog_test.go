package workflows_test

// Run from the repository root in an isolated environment:
//   go test -count=1 ./.github/workflows/changelog_test.go
//
// The actual run blocks are read from the workflows, not copied into the tests.
// Git mutations affect only disposable repositories under t.TempDir().
import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type workflowFixture struct {
	t    *testing.T
	root string
	bash string
	git  string
	env  []string
}

func newWorkflowFixture(t *testing.T) *workflowFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX filenames and Bash, as used by the workflows")
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
	f := &workflowFixture{t: t, root: filepath.Join(scratch, "repo with spaces"), bash: bash, git: git}
	for _, dir := range []string{f.root, filepath.Join(scratch, "tmp"), filepath.Join(scratch, "hooks")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.env = []string{
		"PATH=" + strings.Join([]string{filepath.Dir(bash), filepath.Dir(git), "/usr/bin", "/bin"}, string(os.PathListSeparator)),
		"LC_ALL=C", "TZ=UTC", "TMPDIR=" + filepath.Join(scratch, "tmp"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ATTR_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=QA", "GIT_AUTHOR_EMAIL=qa@example.invalid",
		"GIT_COMMITTER_NAME=QA", "GIT_COMMITTER_EMAIL=qa@example.invalid",
	}
	f.write("CHANGELOG.md", "# Changelog\n\n## Не выпущено\n\n## 2.0.0 — 2026-11-01\n\n- published note\n")
	f.write("VERSION", "2.0.0\n")
	f.write("changes/unreleased/README.md", "fragment format\n")
	f.gitOK("init", "-q", "-b", "main")
	f.gitOK("config", "core.hooksPath", filepath.Join(scratch, "hooks"))
	f.gitOK("config", "commit.gpgSign", "false")
	f.gitOK("config", "core.fileMode", "true")
	f.gitOK("config", "diff.renames", "true")
	f.commit()
	return f
}

func (f *workflowFixture) write(name, value string) {
	f.t.Helper()
	path := filepath.Join(f.root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *workflowFixture) run(env []string, program string, args ...string) (string, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir, cmd.Env = f.root, append(append([]string{}, f.env...), env...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		f.t.Fatalf("command exceeded its deadline: %s", program)
	}
	return string(out), err
}

func (f *workflowFixture) gitOK(args ...string) string {
	f.t.Helper()
	out, err := f.run(nil, f.git, args...)
	if err != nil {
		f.t.Fatalf("fixture git %q: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(out)
}

func (f *workflowFixture) commit() string {
	f.t.Helper()
	f.gitOK("--literal-pathspecs", "add", "--all", "--", ".")
	f.gitOK("commit", "-qm", "QA fixture")
	return f.gitOK("rev-parse", "HEAD")
}

// These jobs each have one literal run block. Fail loudly if the workflow
// structure changes, rather than silently testing an old copy of its commands.
func workflowRun(t *testing.T, filename, job string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate workflow sources")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), filename))
	if err != nil {
		t.Fatal(err)
	}
	var blocks []string
	inJob := false
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "  "+job+":" {
			inJob = true
			continue
		}
		if !inJob {
			continue
		}
		if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '#' {
			break
		}
		if strings.TrimSpace(line) != "run: |" && strings.TrimSpace(line) != "- run: |" {
			continue
		}
		var body []string
		for i+1 < len(lines) {
			next := lines[i+1]
			if strings.TrimSpace(next) != "" && !strings.HasPrefix(next, "          ") {
				break
			}
			i++
			body = append(body, strings.TrimPrefix(next, "          "))
		}
		blocks = append(blocks, strings.Join(body, "\n"))
	}
	if len(blocks) != 1 || strings.TrimSpace(blocks[0]) == "" {
		t.Fatalf("%s job %q: expected one run block, found %d", filename, job, len(blocks))
	}
	if strings.Contains(blocks[0], "$"+"{{") {
		t.Fatal("run block now contains an Actions expression; the fixture must render it before executing Bash")
	}
	return blocks[0]
}

func (f *workflowFixture) ci(base, branch string) (string, error) {
	f.t.Helper()
	return f.run([]string{"BASE=" + base, "GITHUB_HEAD_REF=" + branch, "GITHUB_EVENT_NAME=pull_request"},
		f.bash, "--noprofile", "--norc", "-e", "-c", workflowRun(f.t, "ci.yml", "changelog"))
}

func (f *workflowFixture) release() (string, error) {
	f.t.Helper()
	return f.run([]string{"GITHUB_REF_NAME=v2.0.0", "GITHUB_OUTPUT=" + filepath.Join(f.root, "github-output")},
		f.bash, "--noprofile", "--norc", "-e", "-c", workflowRun(f.t, "release.yml", "check-version"))
}

func (f *workflowFixture) editChangelog() {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, "CHANGELOG.md"))
	if err != nil {
		f.t.Fatal(err)
	}
	f.write("CHANGELOG.md", string(data)+"\n- direct PR edit\n")
}

func TestChangelogCIRequiresAnActualVersionChange(t *testing.T) {
	for _, kind := range []string{"mode only", "extra trailing newline", "deleted VERSION"} {
		t.Run(kind, func(t *testing.T) {
			f := newWorkflowFixture(t)
			base := f.gitOK("rev-parse", "HEAD")
			f.editChangelog()
			switch kind {
			case "mode only":
				if err := os.Chmod(filepath.Join(f.root, "VERSION"), 0700); err != nil {
					t.Fatal(err)
				}
			case "extra trailing newline":
				f.write("VERSION", "2.0.0\n\n")
			case "deleted VERSION":
				if err := os.Remove(filepath.Join(f.root, "VERSION")); err != nil {
					t.Fatal(err)
				}
			}
			f.commit()
			out, err := f.ci(base, "qa/version-bypass")
			if err == nil {
				t.Fatalf("CHANGELOG edit passed without a new version (%s):\n%s", kind, out)
			}
		})
	}
}

func TestChangelogCIRejectsRenamingChangelogWithoutRelease(t *testing.T) {
	f := newWorkflowFixture(t)
	base := f.gitOK("rev-parse", "HEAD")
	if err := os.Rename(filepath.Join(f.root, "CHANGELOG.md"), filepath.Join(f.root, "HISTORY.md")); err != nil {
		t.Fatal(err)
	}
	f.commit()
	if diff := f.gitOK("diff", "--name-status", base+"...HEAD"); !strings.Contains(diff, "R100\tCHANGELOG.md\tHISTORY.md") {
		t.Fatalf("fixture did not produce a detected rename: %s", diff)
	}
	if out, err := f.ci(base, "qa/rename"); err == nil {
		t.Fatalf("renaming the protected changelog bypassed the check:\n%s", out)
	}
}

func TestChangelogCIMatchesTheFilenameLiterally(t *testing.T) {
	f := newWorkflowFixture(t)
	base := f.gitOK("rev-parse", "HEAD")
	f.write("CHANGELOG-md", "an unrelated file, not CHANGELOG.md\n")
	f.commit()
	if out, err := f.ci(base, "qa/unrelated-file"); err != nil {
		t.Fatalf("a different filename was treated as CHANGELOG.md: %v\n%s", err, out)
	}
}

func TestChangelogCIMergeMainUsesCurrentBase(t *testing.T) {
	for _, mainChangesVersion := range []bool{false, true} {
		t.Run(fmt.Sprintf("main_changes_version=%t", mainChangesVersion), func(t *testing.T) {
			f := newWorkflowFixture(t)
			f.gitOK("checkout", "-qb", "feature")
			if mainChangesVersion {
				f.editChangelog() // Must still fail after importing VERSION from main.
			} else {
				f.write("changes/unreleased/feature.md", "- PR fragment\n")
			}
			f.commit()
			f.gitOK("checkout", "-q", "main")
			if mainChangesVersion {
				f.write("VERSION", "2.0.1\n")
			} else {
				f.editChangelog() // Must not be attributed to this PR.
			}
			base := f.commit()
			f.gitOK("checkout", "-q", "feature")
			f.gitOK("merge", "-q", "--no-ff", "-m", "merge main into PR", "main")
			// Match checkout's refs/pull/<n>/merge: base is its first parent.
			f.gitOK("checkout", "-q", "--detach", base)
			f.gitOK("merge", "-q", "--no-ff", "-m", "synthetic PR merge", "feature")
			if got := f.gitOK("merge-base", base, "HEAD"); got != base {
				t.Fatalf("incorrect merge fixture: base=%s merge-base=%s", base, got)
			}
			out, err := f.ci(base, "feature")
			if (err != nil) != mainChangesVersion {
				t.Fatalf("changes imported from main affected the PR decision: error=%v\n%s", err, out)
			}
		})
	}
}

func TestChangelogCIControlsAndShellNames(t *testing.T) {
	for _, scenario := range []string{"fragment", "direct edit", "release", "newline filename", "bad base"} {
		t.Run(scenario, func(t *testing.T) {
			f := newWorkflowFixture(t)
			base := f.gitOK("rev-parse", "HEAD")
			wantFailure := false
			switch scenario {
			case "fragment", "bad base":
				f.write("changes/unreleased/$(touch FILE_INJECTED).md", "- literal filename\n")
				if scenario == "bad base" {
					base = strings.Repeat("0", 40)
					wantFailure = true
				}
			case "direct edit", "release", "newline filename":
				f.editChangelog()
				wantFailure = scenario != "release"
				if scenario == "release" {
					f.write("VERSION", "2.0.1\n")
				}
				if scenario == "newline filename" {
					f.write("note\nVERSION\n.md", "- must not forge a VERSION diff entry\n")
					f.gitOK("config", "core.quotePath", "false")
				}
			}
			f.commit()
			branch := "qa/$(touch$" + "{IFS}BRANCH_INJECTED)"
			f.gitOK("check-ref-format", "--branch", branch)
			out, err := f.ci(base, branch)
			if (err != nil) != wantFailure {
				t.Fatalf("wrong CI decision: error=%v, want failure=%t\n%s", err, wantFailure, out)
			}
			for _, marker := range []string{"BRANCH_INJECTED", "FILE_INJECTED"} {
				if _, err := os.Stat(filepath.Join(f.root, marker)); !os.IsNotExist(err) {
					t.Errorf("untrusted name executed a shell command: %s (%v)", marker, err)
				}
			}
		})
	}
}

func TestReleaseGuardBlocksEveryRemainingFragment(t *testing.T) {
	for _, name := range []string{"", "plain.md", "space name.md", "line\nbreak.md", ".hidden.md", "feature/change.md"} {
		t.Run(fmt.Sprintf("fragment=%q", name), func(t *testing.T) {
			f := newWorkflowFixture(t)
			if name != "" {
				f.write("changes/unreleased/"+name, "- pending note\n")
			}
			out, err := f.release()
			if (err != nil) != (name != "") {
				t.Fatalf("wrong release guard decision for %q: %v\n%s", name, err, out)
			}
			data, readErr := os.ReadFile(filepath.Join(f.root, "github-output"))
			if name == "" {
				if readErr != nil || string(data) != "version=2.0.0\n" {
					t.Errorf("validated version was not exported: %q (%v)", data, readErr)
				}
			} else if strings.Contains(string(data), "version=") {
				t.Error("version was exported despite pending fragments")
			}
		})
	}
}

func TestReleaseGuardDoesNotEmitFilenameAsWorkflowCommand(t *testing.T) {
	f := newWorkflowFixture(t)
	const forged = "::warning file=VERSION,line=1::QA_FILENAME_ANNOTATION.md"
	f.write("changes/unreleased/note\n"+forged, "- pending fragment\n")
	out, err := f.release()
	if err == nil {
		t.Fatal("a pending fragment must block release")
	}
	// Runner commands are parsed from stdout. Accept either escaping or a
	// stop-commands/resume wrapper, but never an active command from a filename.
	paused := ""
	for _, line := range strings.Split(out, "\n") {
		// ActionCommand.TryParseV2 requires "::" at the start after TrimStart.
		line = strings.TrimLeft(line, " \t\r")
		if paused != "" {
			if line == "::"+paused+"::" {
				paused = ""
			}
			continue
		}
		if strings.HasPrefix(line, "::stop-commands::") {
			paused = strings.TrimPrefix(line, "::stop-commands::")
			continue
		}
		if strings.HasPrefix(line, forged) {
			t.Fatalf("a fragment filename can forge a GitHub Actions annotation:\n%s", out)
		}
	}
}

// base.sha события pull_request устаревает, если main ушёл вперёд после события:
// refs/pull/N/merge собран на новом main, и правка CHANGELOG.md в main (слияние
// другого PR) не должна приписываться этому PR.
func TestChangelogCIStaleEventBaseIgnoresNewerMain(t *testing.T) {
	f := newWorkflowFixture(t)
	f.gitOK("branch", "-M", "main")
	staleBase := f.gitOK("rev-parse", "HEAD")
	f.gitOK("checkout", "-qb", "feature")
	f.write("changes/unreleased/feature.md", "- PR fragment\n")
	feature := f.commit()
	f.gitOK("checkout", "-q", "main")
	f.editChangelog() // release или ручная правка в main после события PR
	newMain := f.commit()
	f.gitOK("checkout", "-q", "--detach", newMain)
	f.gitOK("merge", "-q", "--no-ff", "-m", "synthetic PR merge", feature)
	if out, err := f.ci(staleBase, "feature"); err != nil {
		t.Fatalf("changes merged into main after the event were attributed to the PR: %v\n%s", err, out)
	}
}
