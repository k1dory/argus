package rules

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// MaxRuleFileBytes — предел файла правила: правило — десятки строк YAML.
const MaxRuleFileBytes = 1 << 20

// readRuleFile — содержимое файла правила. Только обычный файл (ссылка — по
// цели): FIFO без писателя или устройство в каталоге правил вешали ReadFile, а
// с ним старт и перечитывание движка. Открытие — неблокирующее, размер — не
// больше MaxRuleFileBytes.
func readRuleFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("не обычный файл (%s)", st.Mode().Type())
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return nil, err
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("не обычный файл (%s)", st.Mode().Type())
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxRuleFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxRuleFileBytes {
		return nil, fmt.Errorf("файл правила больше %d байт", MaxRuleFileBytes)
	}
	return raw, nil
}
