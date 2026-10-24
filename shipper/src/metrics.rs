//! Счётчики шиппера и минимальный HTTP для `/healthz` и `/metrics`.
//!
//! Без HTTP-фреймворка: один поток на `std::net::TcpListener`, запросы
//! обрабатываются последовательно — этого достаточно для healthcheck и
//! редкого скрейпа Prometheus. Таймаут чтения защищает от зависшего клиента.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

/// Через сколько секунд без успешного INSERT при ненулевом лаге считать
/// шиппер нездоровым.
pub const STALE_INSERT_SECS: u64 = 300;

#[derive(Debug)]
pub struct Metrics {
    /// Строк, принятых ClickHouse (успешные INSERT).
    pub ingested: AtomicU64,
    /// Строк, отброшенных из-за ошибки разбора JSON.
    pub dropped_parse: AtomicU64,
    /// Строк длиннее MAX_LINE_BYTES, пропущенных целиком.
    pub dropped_oversize: AtomicU64,
    /// Неуспешных попыток INSERT (ретраи считаются каждый).
    pub insert_errors: AtomicU64,
    /// Успешных INSERT (батчей).
    pub inserts_ok: AtomicU64,
    /// Unix-время последнего успешного INSERT, 0 — ещё не было.
    pub last_insert_ok_at: AtomicU64,
    /// Байт в файле после чекпоинта по последнему stat.
    pub lag_bytes: AtomicU64,
    /// Строк в батче, который сейчас отправляется (ретраи INSERT); 0 — нет.
    pub pending_rows: AtomicU64,
    /// Текущее смещение чтения.
    pub offset: AtomicU64,
    /// Файл алертов открыт и stat проходит.
    pub file_ok: AtomicBool,
    /// Unix-время старта процесса — точка отсчёта, пока INSERT ещё не было.
    pub started_at: AtomicU64,
}

pub static METRICS: Metrics = Metrics::new();

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub const fn new() -> Self {
        Metrics {
            ingested: AtomicU64::new(0),
            dropped_parse: AtomicU64::new(0),
            dropped_oversize: AtomicU64::new(0),
            insert_errors: AtomicU64::new(0),
            inserts_ok: AtomicU64::new(0),
            last_insert_ok_at: AtomicU64::new(0),
            lag_bytes: AtomicU64::new(0),
            pending_rows: AtomicU64::new(0),
            offset: AtomicU64::new(0),
            file_ok: AtomicBool::new(false),
            started_at: AtomicU64::new(0),
        }
    }

    pub fn mark_started(&self, now: u64) {
        self.started_at.store(now, Ordering::Relaxed);
    }

    pub fn insert_ok(&self, rows: u64, now: u64) {
        self.inserts_ok.fetch_add(1, Ordering::Relaxed);
        self.ingested.fetch_add(rows, Ordering::Relaxed);
        self.last_insert_ok_at.store(now, Ordering::Relaxed);
    }

    /// Ok — здоров; Err — причина для тела 503.
    pub fn health(&self, now: u64) -> Result<(), String> {
        if !self.file_ok.load(Ordering::Relaxed) {
            return Err("alerts file unavailable".to_string());
        }
        let lag = self.lag_bytes.load(Ordering::Relaxed);
        let pending = self.pending_rows.load(Ordering::Relaxed);
        if lag == 0 && pending == 0 {
            return Ok(());
        }
        let last = self.last_insert_ok_at.load(Ordering::Relaxed);
        let reference = last.max(self.started_at.load(Ordering::Relaxed));
        let idle = now.saturating_sub(reference);
        if idle > STALE_INSERT_SECS {
            let errors = self.insert_errors.load(Ordering::Relaxed);
            return Err(format!(
                "no successful insert for {idle}s while lag is {lag} bytes and {pending} rows are pending ({errors} insert errors total)"
            ));
        }
        Ok(())
    }

    pub fn render(&self, now: u64) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut out = String::with_capacity(1024);
        let mut m = |name: &str, kind: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
            ));
        };
        m(
            "shipper_ingested_total",
            "counter",
            "Rows accepted by ClickHouse.",
            g(&self.ingested),
        );
        m(
            "shipper_dropped_parse_total",
            "counter",
            "Lines dropped: malformed JSON.",
            g(&self.dropped_parse),
        );
        m(
            "shipper_dropped_oversize_total",
            "counter",
            "Lines dropped: longer than MAX_LINE_BYTES.",
            g(&self.dropped_oversize),
        );
        m(
            "shipper_insert_errors_total",
            "counter",
            "Failed INSERT attempts.",
            g(&self.insert_errors),
        );
        m(
            "shipper_inserts_ok_total",
            "counter",
            "Successful INSERT batches.",
            g(&self.inserts_ok),
        );
        m(
            "shipper_last_insert_ok_timestamp_seconds",
            "gauge",
            "Unix time of the last successful INSERT (0 = never).",
            g(&self.last_insert_ok_at),
        );
        m(
            "shipper_lag_bytes",
            "gauge",
            "Bytes in alerts file past the checkpoint.",
            g(&self.lag_bytes),
        );
        m(
            "shipper_pending_rows",
            "gauge",
            "Rows in the batch currently being retried against ClickHouse (0 = none).",
            g(&self.pending_rows),
        );
        m(
            "shipper_offset_bytes",
            "gauge",
            "Current read offset in alerts file.",
            g(&self.offset),
        );
        m(
            "shipper_file_ok",
            "gauge",
            "1 if the alerts file is open and stat succeeds.",
            u64::from(self.file_ok.load(Ordering::Relaxed)),
        );
        m(
            "shipper_healthy",
            "gauge",
            "1 if /healthz would return 200.",
            u64::from(self.health(now).is_ok()),
        );
        out
    }
}

/// Ответ на путь запроса: (код, content-type, тело).
pub fn respond(m: &Metrics, path: &str, now: u64) -> (u16, &'static str, String) {
    let path = path.split('?').next().unwrap_or("");
    match path {
        "/healthz" => match m.health(now) {
            Ok(()) => (200, "text/plain; charset=utf-8", "ok\n".to_string()),
            Err(reason) => (
                503,
                "text/plain; charset=utf-8",
                format!("unhealthy: {reason}\n"),
            ),
        },
        "/metrics" => (
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            m.render(now),
        ),
        _ => (404, "text/plain; charset=utf-8", "not found\n".to_string()),
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Bad Request",
    }
}

fn handle(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 1024];
    let mut n = 0;
    // Читаем до конца первой строки запроса; заголовки нам не нужны.
    while n < buf.len() {
        match stream.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => {
                n += k;
                if buf[..n].windows(2).any(|w| w == b"\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (code, ctype, body) = if method == "GET" || method == "HEAD" {
        respond(&METRICS, path, now_secs())
    } else {
        (
            400,
            "text/plain; charset=utf-8",
            "bad request\n".to_string(),
        )
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(code),
        body.len()
    );
    if method != "HEAD" {
        let _ = stream.write_all(body.as_bytes());
    }
    let _ = stream.flush();
}

/// Слушает `addr` в отдельном потоке; возвращает фактический адрес.
pub fn serve(addr: &str) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    std::thread::Builder::new()
        .name("health-http".into())
        .spawn(move || {
            info!(addr = %local, "health/metrics endpoint listening");
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => handle(stream),
                    Err(e) => warn!("health endpoint accept failed: {e}"),
                }
            }
        })?;
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(now: u64) -> Metrics {
        let m = Metrics::new();
        m.mark_started(now);
        m.file_ok.store(true, Ordering::Relaxed);
        m
    }

    #[test]
    fn unhealthy_when_file_unavailable() {
        let m = Metrics::new();
        m.mark_started(1000);
        let (code, _, body) = respond(&m, "/healthz", 1000);
        assert_eq!(code, 503);
        assert!(body.contains("alerts file unavailable"));
    }

    #[test]
    fn healthy_when_idle_without_lag() {
        let m = fresh(1000);
        // Долго нет INSERT, но и лага нет — идл, это нормально.
        assert_eq!(respond(&m, "/healthz", 1000 + 3600).0, 200);
    }

    #[test]
    fn unhealthy_when_lag_and_no_insert_for_five_minutes() {
        let m = fresh(1000);
        m.lag_bytes.store(10, Ordering::Relaxed);
        assert_eq!(respond(&m, "/healthz", 1000 + STALE_INSERT_SECS).0, 200);
        let (code, _, body) = respond(&m, "/healthz", 1000 + STALE_INSERT_SECS + 1);
        assert_eq!(code, 503);
        assert!(body.contains("lag is 10 bytes"));

        // Успешный INSERT сбрасывает отсчёт.
        m.insert_ok(5, 1000 + STALE_INSERT_SECS + 1);
        assert_eq!(respond(&m, "/healthz", 1000 + STALE_INSERT_SECS + 2).0, 200);
        assert_eq!(m.ingested.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn unhealthy_when_batch_stuck_without_lag() {
        // ClickHouse лёг: файл дочитан (lag 0), но батч крутится в ретраях.
        let m = fresh(1000);
        m.pending_rows.store(500, Ordering::Relaxed);
        m.insert_errors.fetch_add(7, Ordering::Relaxed);
        assert_eq!(respond(&m, "/healthz", 1000 + STALE_INSERT_SECS).0, 200);
        let (code, _, body) = respond(&m, "/healthz", 1000 + STALE_INSERT_SECS + 1);
        assert_eq!(code, 503, "{body}");
        assert!(body.contains("500 rows are pending"), "{body}");
        assert!(body.contains("7 insert errors"), "{body}");
        assert!(m
            .render(1000 + STALE_INSERT_SECS + 1)
            .contains("shipper_healthy 0"));

        // INSERT прошёл, батч ушёл — снова здоров.
        m.insert_ok(500, 1000 + STALE_INSERT_SECS + 1);
        m.pending_rows.store(0, Ordering::Relaxed);
        assert_eq!(respond(&m, "/healthz", 1000 + 2 * STALE_INSERT_SECS).0, 200);
    }

    #[test]
    fn metrics_render_prometheus_text() {
        let m = fresh(1000);
        m.dropped_parse.fetch_add(3, Ordering::Relaxed);
        m.dropped_oversize.fetch_add(1, Ordering::Relaxed);
        m.insert_errors.fetch_add(2, Ordering::Relaxed);
        m.insert_ok(42, 1500);
        let (code, ctype, body) = respond(&m, "/metrics?x=1", 1600);
        assert_eq!(code, 200);
        assert!(ctype.starts_with("text/plain"));
        for line in [
            "shipper_ingested_total 42",
            "shipper_dropped_parse_total 3",
            "shipper_dropped_oversize_total 1",
            "shipper_insert_errors_total 2",
            "shipper_inserts_ok_total 1",
            "shipper_pending_rows 0",
            "shipper_last_insert_ok_timestamp_seconds 1500",
            "shipper_file_ok 1",
            "shipper_healthy 1",
            "# TYPE shipper_ingested_total counter",
        ] {
            assert!(body.contains(line), "missing {line:?} in:\n{body}");
        }
        assert_eq!(respond(&m, "/nope", 1600).0, 404);
    }

    #[test]
    fn http_endpoint_answers_over_tcp() {
        let addr = serve("127.0.0.1:0").unwrap();
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.contains("shipper_ingested_total"));

        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"POST /metrics HTTP/1.1\r\n\r\n").unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    }
}
