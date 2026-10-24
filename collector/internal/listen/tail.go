package listen

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"
)

// TailFile — построчное чтение растущего файла (audit-лог WAF, error-лог,
// JSON-лог Caddy). Ротация по inode или усечение — переоткрытие с начала.
// Без from_start начинает с конца файла (старое не перечитываем), state в памяти.
type TailFile struct {
	Path      string
	Source    string            // метка источника для health/metrics
	FromStart bool              // читать существующий файл с начала (демо), иначе только новые строки
	Handle    func(line string) // вызывается на каждую непустую строку
}

func (t *TailFile) Run(ctx context.Context) {
	var (
		f        *os.File
		reader   *bufio.Reader
		inode    uint64
		offset   int64 // позиция чтения в файле
		lastSize int64 // размер при прошлом опросе — ловим усечение, даже если файл успел дорасти
		pending  string
		warned   bool
	)
	open := func(seekEnd bool) {
		if f != nil {
			f.Close()
			f = nil
		}
		fh, err := os.Open(t.Path)
		if err != nil {
			if !warned {
				slog.Warn("tail: файл недоступен, жду появления", "path", t.Path, "err", err)
				warned = true
			}
			return
		}
		st, err := fh.Stat()
		if err != nil {
			fh.Close()
			return
		}
		offset = 0
		if seekEnd {
			offset, _ = fh.Seek(0, io.SeekEnd)
		}
		inode, lastSize, pending, warned = inodeOf(st), st.Size(), "", false
		f, reader = fh, bufio.NewReaderSize(fh, 1<<20)
		slog.Info("tail", "path", t.Path, "from_end", seekEnd)
	}
	open(!t.FromStart)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case <-tick.C:
		}
		if f == nil {
			open(false) // файл появился позже старта — читаем с начала
			if f == nil {
				continue
			}
		}
		// ротация (новый inode) или усечение: файл короче позиции чтения ИЛИ короче,
		// чем был при прошлом опросе (truncate + быстрая дозапись до прежнего размера)
		if st, err := os.Stat(t.Path); err == nil {
			if ino := inodeOf(st); ino != inode || st.Size() < offset || st.Size() < lastSize {
				open(false)
				if f == nil {
					continue
				}
			} else {
				lastSize = st.Size()
			}
		}
		for {
			chunk, err := reader.ReadString('\n')
			if chunk != "" {
				offset += int64(len(chunk))
				pending += chunk
			}
			if strings.HasSuffix(pending, "\n") {
				line := strings.TrimSpace(pending)
				pending = ""
				if line != "" {
					Guard("tail "+t.Source, func() { t.Handle(line) })
				}
			}
			if err != nil { // io.EOF — неполная строка остаётся в pending до следующего тика
				break
			}
		}
	}
}

func inodeOf(st os.FileInfo) uint64 {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return uint64(sys.Ino)
	}
	return 0
}
