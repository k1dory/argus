package registry

import (
	"os"
	"path/filepath"
)

// LoadRepo — реестр из рабочей копии (тесты пакетов): rules/ и fixtures/events
// корня репозитория, найденного вверх от текущего каталога.
func LoadRepo() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, "fixtures", "events")); err == nil && st.IsDir() {
			return LoadDirs(filepath.Join(dir, "rules"), filepath.Join(dir, "fixtures", "events"))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return os.ErrNotExist
		}
		dir = parent
	}
}
