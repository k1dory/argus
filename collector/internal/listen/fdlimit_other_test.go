//go:build !unix

package listen

import "testing"

func needFDs(t *testing.T, n uint64) {
	t.Helper()
	t.Skipf("проверка лимита дескрипторов (%d) — только на unix", n)
}
