mod metrics;
mod model;
mod reader;
mod sink;
mod state;

use std::env;
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use tracing::{info, warn};

use metrics::METRICS;
use model::Row;
use reader::{Line, LineReader};
use sink::Sink;
use state::Checkpoint;

struct Config {
    alerts_file: PathBuf,
    state_file: PathBuf,
    batch_size: usize,
    flush_interval: Duration,
    poll_interval: Duration,
    max_line_bytes: usize,
    health_addr: String,
    clickhouse_url: String,
    clickhouse_db: String,
    clickhouse_table: String,
    clickhouse_user: String,
    clickhouse_password: String,
    /// PEM с CA сертификата ClickHouse; обязателен при https:// в CLICKHOUSE_URL.
    clickhouse_ca_file: Option<PathBuf>,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    fn from_env() -> Config {
        Config {
            alerts_file: env_or("ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json").into(),
            state_file: env_or("STATE_FILE", "/state/shipper.json").into(),
            batch_size: env_or("BATCH_SIZE", "500").parse().unwrap_or(500),
            flush_interval: Duration::from_millis(
                env_or("FLUSH_INTERVAL_MS", "2000").parse().unwrap_or(2000),
            ),
            poll_interval: Duration::from_millis(env_or("POLL_MS", "500").parse().unwrap_or(500)),
            max_line_bytes: env_or("MAX_LINE_BYTES", "4194304")
                .parse()
                .unwrap_or(4 * 1024 * 1024),
            // Пустая строка отключает эндпоинт.
            health_addr: env_or("HEALTH_ADDR", "127.0.0.1:9101"),
            clickhouse_url: env_or("CLICKHOUSE_URL", "http://localhost:8123"),
            clickhouse_db: env_or("CLICKHOUSE_DB", "argus"),
            clickhouse_table: env_or("CLICKHOUSE_TABLE", "wazuh_alerts"),
            clickhouse_user: env_or("CLICKHOUSE_USER", "default"),
            clickhouse_password: env_or("CLICKHOUSE_PASSWORD", ""),
            clickhouse_ca_file: env::var("CLICKHOUSE_CA_FILE")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
        }
    }
}

/// Открытый файл алертов вместе с тем, что нужно для чекпоинта.
struct Source {
    reader: LineReader<BufReader<File>>,
    inode: u64,
    head_len: u64,
    head_hash: u64,
}

impl Source {
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            inode: self.inode,
            offset: self.reader.offset(),
            head_len: self.head_len,
            head_hash: self.head_hash,
        }
    }

    /// Файл открыли пустым или короче 256 байт — отпечаток неполный;
    /// дочитываем его, когда файл подрос (перед сохранением чекпоинта).
    fn refresh_head(&mut self) {
        if self.head_len >= state::HEAD_LEN {
            return;
        }
        if let Ok((len, hash)) = state::head_fingerprint(self.reader.get_ref().get_ref()) {
            self.head_len = len;
            self.head_hash = hash;
        }
    }
}

fn open_at(cfg: &Config, cp: Checkpoint) -> anyhow::Result<Source> {
    let file = File::open(&cfg.alerts_file)
        .with_context(|| format!("cannot open {}", cfg.alerts_file.display()))?;
    let meta = file.metadata()?;
    let inode = meta.ino();
    let (head_len, head_hash) = state::head_fingerprint(&file)?;
    // Продолжаем только если это тот же файл (inode и начало) и он не усох.
    let offset = if inode == cp.inode && meta.len() >= cp.offset {
        if state::head_matches(&file, cp)? {
            cp.offset
        } else {
            info!(
                inode,
                "inode reused by a different file (head mismatch), starting from 0"
            );
            0
        }
    } else {
        0
    };
    let mut buf = BufReader::with_capacity(64 * 1024, file);
    buf.seek(SeekFrom::Start(offset))?;
    Ok(Source {
        reader: LineReader::new(buf, offset, cfg.max_line_bytes),
        inode,
        head_len,
        head_hash,
    })
}

/// Ждёт появления файла (менеджер ещё не стартовал / ротация в процессе).
fn open_retry(cfg: &Config, cp: Checkpoint) -> Source {
    loop {
        match open_at(cfg, cp) {
            Ok(src) => {
                METRICS.file_ok.store(true, Ordering::Relaxed);
                METRICS.offset.store(src.reader.offset(), Ordering::Relaxed);
                return src;
            }
            Err(e) => {
                METRICS.file_ok.store(false, Ordering::Relaxed);
                warn!("{e:#}; retrying in 5s");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

/// Разбирает строку; любая ошибка — счётчик и warn, но не остановка.
fn handle_line(bytes: &[u8], batch: &mut Vec<Row>, offset: u64) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    match Row::parse(trimmed) {
        Ok(row) => {
            batch.push(row);
            true
        }
        Err(e) => {
            METRICS.dropped_parse.fetch_add(1, Ordering::Relaxed);
            warn!(offset, "skipping line: {e:#}");
            false
        }
    }
}

fn note_oversize(cfg: &Config, offset: u64) {
    METRICS.dropped_oversize.fetch_add(1, Ordering::Relaxed);
    warn!(
        offset,
        max_line_bytes = cfg.max_line_bytes,
        "dropping oversize line"
    );
}

/// Дочитывает открытый файл до EOF (полные строки), возвращает число строк.
fn drain(src: &mut Source, cfg: &Config, batch: &mut Vec<Row>) -> usize {
    let mut n_lines = 0;
    loop {
        match src.reader.read_line() {
            Ok(Line::Complete(bytes)) => {
                if handle_line(&bytes, batch, src.reader.offset()) {
                    n_lines += 1;
                }
            }
            Ok(Line::Oversize) => note_oversize(cfg, src.reader.offset()),
            Ok(Line::Eof) => return n_lines,
            Err(e) => {
                warn!("read error while draining: {e}");
                return n_lines;
            }
        }
    }
}

/// Обновляет lag_bytes по текущему размеру файла: пока flush крутится в
/// ретраях, основной цикл stat не делает, и /healthz видел бы устаревший 0.
fn refresh_lag(src: &Source) {
    if let Ok(meta) = src.reader.get_ref().get_ref().metadata() {
        METRICS.lag_bytes.store(
            meta.len().saturating_sub(src.reader.offset()),
            Ordering::Relaxed,
        );
    }
}

fn flush(sink: &Sink, batch: &mut Vec<Row>, cfg: &Config, src: &mut Source) {
    if batch.is_empty() {
        return;
    }
    refresh_lag(src);
    src.refresh_head();
    let cp = src.checkpoint();
    let body = match Sink::render(batch) {
        Ok(body) => body,
        Err(e) => {
            // Невозможно на практике (Row всегда сериализуем), но терять
            // чекпоинт из-за этого нельзя.
            warn!(
                "cannot serialize batch, dropping {} rows: {e:#}",
                batch.len()
            );
            METRICS
                .dropped_parse
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            batch.clear();
            return;
        }
    };
    // Пока батч не принят, /healthz считает его «застрявшим»: если ClickHouse
    // лежит дольше STALE_INSERT_SECS — 503 даже при нулевом лаге по файлу.
    METRICS
        .pending_rows
        .store(batch.len() as u64, Ordering::Relaxed);
    let mut backoff = Duration::from_secs(1);
    loop {
        match sink.send(&body) {
            Ok(()) => {
                info!(rows = batch.len(), offset = cp.offset, "flushed batch");
                METRICS.insert_ok(batch.len() as u64, metrics::now_secs());
                METRICS.pending_rows.store(0, Ordering::Relaxed);
                batch.clear();
                if let Err(e) = state::save(&cfg.state_file, cp) {
                    warn!("cannot save checkpoint: {e:#}");
                }
                return;
            }
            Err(e) => {
                METRICS.insert_errors.fetch_add(1, Ordering::Relaxed);
                warn!("insert failed, retrying in {backoff:?}: {e:#}");
                thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::from_env();
    METRICS.mark_started(metrics::now_secs());
    if !cfg.health_addr.is_empty() {
        match metrics::serve(&cfg.health_addr) {
            Ok(_) => {}
            Err(e) => warn!(addr = %cfg.health_addr, "cannot start health endpoint: {e:#}"),
        }
    }

    let sink = Sink::new(
        &cfg.clickhouse_url,
        &cfg.clickhouse_db,
        &cfg.clickhouse_table,
        &cfg.clickhouse_user,
        &cfg.clickhouse_password,
        cfg.clickhouse_ca_file.as_deref(),
    )
    .context("clickhouse client")?;

    let cp = state::load(&cfg.state_file);
    info!(
        file = %cfg.alerts_file.display(),
        inode = cp.inode,
        offset = cp.offset,
        max_line_bytes = cfg.max_line_bytes,
        "starting wazuh-shipper"
    );

    let mut src = open_retry(&cfg, cp);
    let mut batch: Vec<Row> = Vec::with_capacity(cfg.batch_size);
    let mut last_flush = Instant::now();

    loop {
        match src.reader.read_line() {
            Ok(Line::Complete(bytes)) => {
                let offset = src.reader.offset();
                handle_line(&bytes, &mut batch, offset);
                METRICS.offset.store(offset, Ordering::Relaxed);
                if batch.len() >= cfg.batch_size {
                    flush(&sink, &mut batch, &cfg, &mut src);
                    last_flush = Instant::now();
                }
                continue;
            }
            Ok(Line::Oversize) => {
                note_oversize(&cfg, src.reader.offset());
                METRICS.offset.store(src.reader.offset(), Ordering::Relaxed);
                continue;
            }
            // Неполная строка на EOF остаётся в буфере читателя и ждёт `\n`.
            Ok(Line::Eof) => {}
            Err(e) => warn!("read error: {e}"),
        }

        if !batch.is_empty() && last_flush.elapsed() >= cfg.flush_interval {
            flush(&sink, &mut batch, &cfg, &mut src);
            last_flush = Instant::now();
        }

        // Detect rotation (new inode) or truncation (file shrank).
        match std::fs::metadata(&cfg.alerts_file) {
            Ok(meta) if meta.ino() != src.inode || meta.len() < src.reader.offset() => {
                // Ротация: у нас всё ещё открыт старый inode — дочитываем его
                // до конца, иначе хвост, дописанный между последним чтением и
                // stat, потерялся бы.
                if meta.ino() != src.inode {
                    let drained = drain(&mut src, &cfg, &mut batch);
                    if drained > 0 {
                        info!(drained, "drained tail of rotated file");
                    }
                }
                flush(&sink, &mut batch, &cfg, &mut src);
                last_flush = Instant::now();
                info!("alerts file rotated or truncated, reopening");
                src = open_retry(&cfg, Checkpoint::default());
                continue;
            }
            Ok(meta) => {
                METRICS.file_ok.store(true, Ordering::Relaxed);
                METRICS.lag_bytes.store(
                    meta.len().saturating_sub(src.reader.offset()),
                    Ordering::Relaxed,
                );
            }
            Err(e) => {
                METRICS.file_ok.store(false, Ordering::Relaxed);
                warn!("cannot stat alerts file: {e}");
            }
        }

        thread::sleep(cfg.poll_interval);
    }
}
