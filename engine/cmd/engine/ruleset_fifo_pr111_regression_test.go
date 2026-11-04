//go:build linux || darwin

package main

// Регрессия PR #111: некорректный пользовательский каталог не должен
// останавливать загрузку поставляемых правил. Только локальный FIFO в t.TempDir,
// без данных и без писателя; дочерний процесс ограничен тремя секундами.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const pr111LoadStarted = "PR111: loading user rules"

func TestPR111UserFIFOHelper(t *testing.T) {
	if os.Getenv("ARGUS_PR111_FIFO_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, pr111LoadStarted)
	dirs := ruleSet{shipped: os.Getenv("RULES_DIR"), user: os.Getenv("RULES_USER_DIR")}
	loaded, rejected, err := dirs.load()
	if err != nil || len(loaded) != 1 || len(rejected) != 1 || rejected[0].Reason != rejectParseError {
		t.Fatalf("invalid user catalogue must be rejected while shipped detection remains available: rules=%d rejected=%+v err=%v", len(loaded), rejected, err)
	}
}

func TestPR111UserFIFOIsRejectedWithoutBlockingShippedRules(t *testing.T) {
	shipped := rulesDirWith(t, map[string]string{"shipped.yml": simpleRule("qa-shipped", "shipped.action")})
	user := rulesDirWith(t, map[string]string{"valid.yml": simpleRule("qa-custom", "custom.action")})
	if err := syscall.Mkfifo(filepath.Join(user, "broken.yml"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestPR111UserFIFOHelper$")
	scratch := t.TempDir()
	cmd.Env = []string{
		"ARGUS_PR111_FIFO_HELPER=1",
		"RULES_DIR=" + shipped,
		"RULES_USER_DIR=" + user,
		"HOME=" + scratch,
		"TMPDIR=" + scratch,
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		if !strings.Contains(string(out), pr111LoadStarted) {
			t.Fatalf("helper did not reach the loader before deadline: %v\n%s", ctx.Err(), out)
		}
		t.Fatalf("user FIFO blocks ruleSet.load and all shipped detection instead of rejecting the user catalogue: %v\n%s", ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("loader helper: %v\n%s", err, out)
	}
}
