//go:build unix

package listen

import (
	"syscall"
	"testing"
)

// needFDs поднимает мягкий лимит дескрипторов до n (в пределах жёсткого) или
// пропускает тест: при нехватке fd ошибку ловит то клиент, то accept
// сервера, и тест падал или проходил в зависимости от ulimit хоста.
func needFDs(t *testing.T, n uint64) {
	t.Helper()
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Skipf("лимит дескрипторов не читается: %v", err)
	}
	if lim.Cur >= n {
		return
	}
	if lim.Max < n {
		t.Skipf("нужно %d дескрипторов, жёсткий лимит хоста %d (ulimit -Hn): поднимите его, например docker run --ulimit nofile=65536", n, lim.Max)
	}
	old := lim
	lim.Cur = n
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Skipf("не удалось поднять лимит дескрипторов до %d: %v", n, err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old) })
}
