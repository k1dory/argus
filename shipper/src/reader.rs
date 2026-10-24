//! Построчное чтение alerts.json с ограничением длины строки.
//!
//! Строка отдаётся как байты (менеджер может писать не-UTF8 — конвертация
//! `from_utf8_lossy` на стороне вызывающего). Строка длиннее `max_line`
//! байт не буферизуется целиком: читатель переходит в режим пропуска и
//! выбрасывает байты до следующего `\n`, продвигая смещение, — память
//! ограничена размером буфера `BufReader`, а не длиной строки.
//!
//! Смещение (`offset`) всегда указывает на начало ещё не отданной строки:
//! неполная строка на конце файла держится во внутреннем буфере и в
//! чекпоинт не попадает; после рестарта она будет перечитана с начала.
//! Исключение — режим пропуска: там смещение продвигается по мере
//! выбрасывания байтов, иначе оверсайз-строка без `\n` заставила бы держать
//! её в памяти до появления перевода строки.

use std::io::{self, BufRead};

#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// Полная строка без завершающего `\n`.
    Complete(Vec<u8>),
    /// Строка длиннее лимита: её начало выброшено, хвост до `\n` будет
    /// пропущен (возможно, за несколько вызовов, если `\n` ещё не дописан).
    Oversize,
    /// Данные кончились; неполная строка (если есть) ждёт продолжения.
    Eof,
}

pub struct LineReader<R> {
    inner: R,
    offset: u64,
    max_line: usize,
    partial: Vec<u8>,
    skipping: bool,
}

impl<R: BufRead> LineReader<R> {
    pub fn new(inner: R, offset: u64, max_line: usize) -> Self {
        LineReader {
            inner,
            offset,
            max_line,
            partial: Vec::new(),
            skipping: false,
        }
    }

    /// Смещение первого байта, который ещё не был отдан как полная строка
    /// (или не был пропущен) — то, что можно сохранять в чекпоинт.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn read_line(&mut self) -> io::Result<Line> {
        loop {
            let avail = self.inner.fill_buf()?;
            if avail.is_empty() {
                return Ok(Line::Eof);
            }
            let newline = avail.iter().position(|&b| b == b'\n');
            match newline {
                Some(i) => {
                    let consumed = i + 1;
                    if self.skipping {
                        // Хвост оверсайз-строки дочитан — дальше обычный режим.
                        self.inner.consume(consumed);
                        self.offset += consumed as u64;
                        self.skipping = false;
                        continue;
                    }
                    if self.partial.len() + i > self.max_line {
                        // Начало строки уже накоплено в partial, конец — в буфере:
                        // выбрасываем всё вместе с `\n`.
                        let dropped = self.partial.len() as u64 + consumed as u64;
                        self.partial = Vec::new();
                        self.inner.consume(consumed);
                        self.offset += dropped;
                        return Ok(Line::Oversize);
                    }
                    let mut line = std::mem::take(&mut self.partial);
                    line.extend_from_slice(&avail[..i]);
                    self.inner.consume(consumed);
                    self.offset += line.len() as u64 + 1;
                    return Ok(Line::Complete(line));
                }
                None => {
                    let n = avail.len();
                    if self.skipping {
                        self.inner.consume(n);
                        self.offset += n as u64;
                        continue;
                    }
                    if self.partial.len() + n > self.max_line {
                        // Лимит превышен, а `\n` ещё не видно: выбрасываем всё,
                        // что накопили, и пропускаем до конца строки.
                        let dropped = self.partial.len() as u64 + n as u64;
                        self.partial = Vec::new();
                        self.inner.consume(n);
                        self.offset += dropped;
                        self.skipping = true;
                        return Ok(Line::Oversize);
                    }
                    self.partial.extend_from_slice(avail);
                    self.inner.consume(n);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Line, LineReader};
    use std::fs::OpenOptions;
    use std::io::{BufReader, Cursor, Write};

    fn reader(data: &[u8], max: usize) -> LineReader<Cursor<Vec<u8>>> {
        LineReader::new(Cursor::new(data.to_vec()), 0, max)
    }

    #[test]
    fn splits_lines_and_tracks_offset() {
        let mut r = reader(b"a\nbb\n\nccc\n", 1024);
        assert_eq!(r.read_line().unwrap(), Line::Complete(b"a".to_vec()));
        assert_eq!(r.offset(), 2);
        assert_eq!(r.read_line().unwrap(), Line::Complete(b"bb".to_vec()));
        assert_eq!(r.read_line().unwrap(), Line::Complete(b"".to_vec()));
        assert_eq!(r.read_line().unwrap(), Line::Complete(b"ccc".to_vec()));
        assert_eq!(r.offset(), 10);
        assert_eq!(r.read_line().unwrap(), Line::Eof);
        assert_eq!(r.offset(), 10);
    }

    #[test]
    fn non_utf8_bytes_are_delivered_verbatim() {
        let mut r = reader(b"{\"a\":\"\xff\xfe\"}\n", 1024);
        let Line::Complete(bytes) = r.read_line().unwrap() else {
            panic!("expected a complete line");
        };
        assert_eq!(bytes, b"{\"a\":\"\xff\xfe\"}");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains('\u{FFFD}'));
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn truncated_tail_is_held_until_newline_arrives() {
        let path = std::env::temp_dir().join(format!(
            "shipper-reader-{}-{}.log",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, b"{\"ok\":1}\n{\"trunc").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mut r = LineReader::new(BufReader::with_capacity(16, file), 0, 1024);

        assert_eq!(
            r.read_line().unwrap(),
            Line::Complete(b"{\"ok\":1}".to_vec())
        );
        assert_eq!(r.read_line().unwrap(), Line::Eof);
        // Смещение остаётся на начале неполной строки.
        assert_eq!(r.offset(), 9);
        assert_eq!(r.read_line().unwrap(), Line::Eof);

        let mut w = OpenOptions::new().append(true).open(&path).unwrap();
        w.write_all(b"ated\":2}\n").unwrap();
        drop(w);

        assert_eq!(
            r.read_line().unwrap(),
            Line::Complete(b"{\"truncated\":2}".to_vec())
        );
        assert_eq!(r.offset(), 9 + 16);
        assert_eq!(r.read_line().unwrap(), Line::Eof);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn oversize_line_with_newline_is_skipped_whole() {
        let mut data = b"{\"a\":1}\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', 5000));
        data.extend_from_slice(b"\n{\"b\":2}\n");
        let mut r = LineReader::new(
            BufReader::with_capacity(64, Cursor::new(data.clone())),
            0,
            4096,
        );
        assert_eq!(
            r.read_line().unwrap(),
            Line::Complete(b"{\"a\":1}".to_vec())
        );
        assert_eq!(r.read_line().unwrap(), Line::Oversize);
        assert_eq!(
            r.read_line().unwrap(),
            Line::Complete(b"{\"b\":2}".to_vec())
        );
        assert_eq!(r.offset(), data.len() as u64);
        assert_eq!(r.read_line().unwrap(), Line::Eof);
    }

    #[test]
    fn ten_megabyte_line_without_newline_is_dropped_and_memory_bounded() {
        let path = std::env::temp_dir().join(format!(
            "shipper-reader-{}-{}.log",
            std::process::id(),
            line!()
        ));
        let big = vec![b'z'; 10 * 1024 * 1024];
        std::fs::write(&path, &big).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mut r = LineReader::new(BufReader::with_capacity(8192, file), 0, 4 * 1024 * 1024);

        // Ровно один сигнал Oversize, потом Eof — строка не буферизуется.
        assert_eq!(r.read_line().unwrap(), Line::Oversize);
        assert_eq!(r.read_line().unwrap(), Line::Eof);
        assert!(r.partial.is_empty());
        assert!(r.skipping);
        assert_eq!(r.offset(), big.len() as u64);

        // Дописали хвост и нормальную строку: хвост тихо выброшен, строка отдана.
        let mut w = OpenOptions::new().append(true).open(&path).unwrap();
        w.write_all(b"tail\n{\"after\":true}\n").unwrap();
        drop(w);
        assert_eq!(
            r.read_line().unwrap(),
            Line::Complete(b"{\"after\":true}".to_vec())
        );
        assert!(!r.skipping);
        assert_eq!(r.offset(), (big.len() + 5 + 15) as u64);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn oversize_line_inside_one_buffer_is_skipped() {
        // `\n` виден в том же буфере, что и превышение лимита.
        let mut r = reader(b"0123456789\nok\n", 8);
        assert_eq!(r.read_line().unwrap(), Line::Oversize);
        assert_eq!(r.offset(), 11);
        assert_eq!(r.read_line().unwrap(), Line::Complete(b"ok".to_vec()));
        assert_eq!(r.offset(), 14);
    }

    #[test]
    fn resumes_from_given_offset() {
        let mut r = LineReader::new(Cursor::new(b"x\n".to_vec()), 100, 1024);
        assert_eq!(r.read_line().unwrap(), Line::Complete(b"x".to_vec()));
        assert_eq!(r.offset(), 102);
    }
}
