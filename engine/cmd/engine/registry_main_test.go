package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/registry"
)

// Реестр поставляемого набора — из рабочей копии (rules/, fixtures/events), как
// в образе движка из его копии.
func TestMain(m *testing.M) {
	if err := registry.LoadRepo(); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
