use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};

use crate::model::Row;

pub struct Sink {
    client: reqwest::blocking::Client,
    url: String,
    query: String,
    user: String,
    password: String,
}

impl Sink {
    /// `ca_file` — PEM с CA, которым подписан сертификат ClickHouse. Для
    /// `https://` обязателен: rustls собран без системных корней (детерминизм
    /// сборки), а внутренний ClickHouse подписан своим CA, не публичным.
    pub fn new(
        url: &str,
        db: &str,
        table: &str,
        user: &str,
        password: &str,
        ca_file: Option<&Path>,
    ) -> anyhow::Result<Sink> {
        let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(30));
        match ca_file {
            Some(path) => {
                let pem = std::fs::read(path).with_context(|| {
                    format!("cannot read CLICKHOUSE_CA_FILE {}", path.display())
                })?;
                let certs = reqwest::Certificate::from_pem_bundle(&pem)
                    .with_context(|| format!("bad PEM in CLICKHOUSE_CA_FILE {}", path.display()))?;
                if certs.is_empty() {
                    bail!("no certificates in CLICKHOUSE_CA_FILE {}", path.display());
                }
                for cert in certs {
                    builder = builder.add_root_certificate(cert);
                }
            }
            None if url
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("https://") =>
            {
                bail!("CLICKHOUSE_URL is https but CLICKHOUSE_CA_FILE is not set: point it at the PEM of the CA that signed the ClickHouse certificate");
            }
            None => {}
        }
        Ok(Sink {
            client: builder.build().context("http client")?,
            url: url.trim_end_matches('/').to_string(),
            query: format!("INSERT INTO {db}.{table} FORMAT JSONEachRow"),
            user: user.to_string(),
            password: password.to_string(),
        })
    }

    /// Сериализует батч один раз; тело переиспользуется между ретраями send().
    pub fn render(rows: &[Row]) -> anyhow::Result<String> {
        let mut body = String::with_capacity(rows.len() * 512);
        for row in rows {
            body.push_str(&serde_json::to_string(row)?);
            body.push('\n');
        }
        Ok(body)
    }

    /// Токен дедупликации: одинаковое тело батча при повторной отправке
    /// (ретрай после падения между insert и чекпоинтом) ClickHouse отбросит
    /// в окне non_replicated_deduplication_window таблицы.
    pub fn dedup_token(body: &str) -> String {
        let mut h = DefaultHasher::new();
        body.hash(&mut h);
        format!("shipper-{:016x}", h.finish())
    }

    pub fn send(&self, body: &str) -> anyhow::Result<()> {
        let token = Self::dedup_token(body);
        let resp = self
            .client
            .post(&self.url)
            .query(&[
                ("query", self.query.as_str()),
                ("input_format_skip_unknown_fields", "1"),
                ("date_time_input_format", "best_effort"),
                ("insert_deduplication_token", token.as_str()),
            ])
            .basic_auth(&self.user, Some(&self.password))
            .body(body.to_owned())
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            bail!("clickhouse returned {status}: {}", text.trim());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Sink;

    // Самоподписанный тестовый сертификат (openssl req -x509, ключ выброшен).
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBhjCCASugAwIBAgIUdtj9nJJ6SwnVDKZWd6r+czndWSIwCgYIKoZIzj0EAwIw\nGDEWMBQGA1UEAwwNYXJndXMtdGVzdC1jYTAeFw0yNjA5MTUxNDUwMzNaFw0zNjA5\nMTIxNDUwMzNaMBgxFjAUBgNVBAMMDWFyZ3VzLXRlc3QtY2EwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARFrw9ofsyhsN3Rx7L6lBncA//sefUmcgfyUh41YJt5tc8N\nAJXR9kwADEcrzGicYZVGiVoxrSV1uiHm4kM6GIu/o1MwUTAdBgNVHQ4EFgQUGuBE\npZrVUqWHfXGbctBaUebmDfwwHwYDVR0jBBgwFoAUGuBEpZrVUqWHfXGbctBaUebm\nDfwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEArbROZ/IRMxRM\nR/ftV4neGk1HI6Gys6OLM8n4klgHlmECIQDXx6GPK38IxSQA3qzkxaNBtryKIzxi\nRYPVt9ajfw8nlw==\n-----END CERTIFICATE-----\n";

    fn new_sink(url: &str, ca: Option<&std::path::Path>) -> anyhow::Result<Sink> {
        Sink::new(url, "argus", "wazuh_alerts", "u", "p", ca)
    }

    // Sink нарочно без Debug (внутри пароль), поэтому текст ошибки достаём так.
    fn err_text(r: anyhow::Result<Sink>) -> String {
        match r {
            Ok(_) => panic!("expected error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn https_requires_ca_file() {
        let err = err_text(new_sink("https://ch:8443", None));
        assert!(err.contains("CLICKHOUSE_CA_FILE"), "{err}");
        assert!(new_sink("HTTPS://ch:8443", None).is_err());
        // Plain http — без CA.
        assert!(new_sink("http://ch:8123", None).is_ok());
    }

    #[test]
    fn ca_file_must_exist_and_hold_certificates() {
        let dir = std::env::temp_dir().join(format!("shipper-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.pem");
        let err = err_text(new_sink("https://ch:8443", Some(&missing)));
        assert!(err.contains("cannot read"), "{err}");

        let empty = dir.join("empty.pem");
        std::fs::write(&empty, "not a pem\n").unwrap();
        assert!(new_sink("https://ch:8443", Some(&empty)).is_err());

        let good = dir.join("ca.pem");
        std::fs::write(&good, TEST_CA_PEM).unwrap();
        assert!(new_sink("https://ch:8443", Some(&good)).is_ok());
        // Bundle из двух сертификатов тоже принимается.
        std::fs::write(&good, format!("{TEST_CA_PEM}{TEST_CA_PEM}")).unwrap();
        assert!(new_sink("https://ch:8443", Some(&good)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_token_is_stable_for_same_body() {
        let a = Sink::dedup_token("{\"a\":1}\n");
        let b = Sink::dedup_token("{\"a\":1}\n");
        let c = Sink::dedup_token("{\"a\":2}\n");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("shipper-"));
    }
}
