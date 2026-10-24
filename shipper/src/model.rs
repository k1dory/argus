use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
struct Agent {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    ip: String,
}

#[derive(Debug, Default, Deserialize)]
struct Manager {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Default, Deserialize)]
struct Mitre {
    #[serde(default)]
    id: Vec<String>,
    #[serde(default)]
    tactic: Vec<String>,
    #[serde(default)]
    technique: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Rule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    level: u8,
    #[serde(default)]
    description: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    firedtimes: u32,
    #[serde(default)]
    mitre: Mitre,
}

#[derive(Debug, Default, Deserialize)]
struct Decoder {
    #[serde(default)]
    name: String,
}

/// Alert as emitted by the Wazuh manager into alerts.json (one JSON object per line).
#[derive(Debug, Deserialize)]
struct RawAlert {
    timestamp: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    agent: Agent,
    #[serde(default)]
    manager: Manager,
    #[serde(default)]
    rule: Rule,
    #[serde(default)]
    decoder: Decoder,
    #[serde(default)]
    location: String,
    #[serde(default)]
    full_log: String,
    #[serde(default)]
    data: serde_json::Value,
}

/// Flattened row matching the argus.wazuh_alerts ClickHouse table (JSONEachRow).
#[derive(Debug, Serialize)]
pub struct Row {
    pub timestamp: String,
    pub alert_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub agent_ip: String,
    pub manager_name: String,
    pub rule_id: u32,
    pub rule_level: u8,
    pub rule_description: String,
    pub rule_groups: Vec<String>,
    pub rule_firedtimes: u32,
    pub mitre_ids: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub decoder_name: String,
    pub location: String,
    pub srcip: String,
    // Поля vulnerability-detector (data.vulnerability.*); пустые у обычных алертов.
    pub vuln_cve: String,
    pub vuln_severity: String,
    pub vuln_package: String,
    pub vuln_package_version: String,
    pub vuln_status: String,
    pub vuln_score: f32,
    pub full_log: String,
    pub raw: String,
}

impl Row {
    pub fn parse(line: &str) -> anyhow::Result<Row> {
        let a: RawAlert = serde_json::from_str(line).context("malformed alert JSON")?;
        let srcip = a
            .data
            .get("srcip")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let vuln = a.data.get("vulnerability");
        let vstr = |path: &[&str]| -> String {
            let mut cur = vuln;
            for key in path {
                cur = cur.and_then(|v| v.get(key));
            }
            cur.and_then(|v| v.as_str()).unwrap_or_default().to_string()
        };
        // CVSS3 приоритетнее CVSS2; менеджер пишет base_score строкой или числом.
        let vuln_score = [
            &["cvss", "cvss3", "base_score"][..],
            &["cvss", "cvss2", "base_score"][..],
        ]
        .iter()
        .find_map(|path| {
            let mut cur = vuln;
            for key in *path {
                cur = cur.and_then(|v| v.get(key));
            }
            cur.and_then(|v| {
                v.as_f64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
        })
        .unwrap_or(0.0) as f32;
        Ok(Row {
            timestamp: a.timestamp,
            alert_id: a.id,
            agent_id: a.agent.id,
            agent_name: a.agent.name,
            agent_ip: a.agent.ip,
            manager_name: a.manager.name,
            rule_id: a.rule.id.parse().unwrap_or(0),
            rule_level: a.rule.level,
            rule_description: a.rule.description,
            rule_groups: a.rule.groups,
            rule_firedtimes: a.rule.firedtimes,
            mitre_ids: a.rule.mitre.id,
            mitre_tactics: a.rule.mitre.tactic,
            mitre_techniques: a.rule.mitre.technique,
            decoder_name: a.decoder.name,
            location: a.location,
            srcip,
            vuln_cve: vstr(&["cve"]),
            vuln_severity: vstr(&["severity"]),
            vuln_package: vstr(&["package", "name"]),
            vuln_package_version: vstr(&["package", "version"]),
            vuln_status: vstr(&["status"]),
            vuln_score,
            full_log: a.full_log,
            raw: line.trim_end().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Row;

    #[test]
    fn parses_documented_alert_shape() {
        let line = r#"{"timestamp":"2026-08-18T12:12:18.684+0000","rule":{"level":12,"description":"PsExec service","id":"110011","groups":["windows","sysmon"],"mitre":{"id":["T1543.003"],"tactic":["Persistence","Privilege Escalation"],"technique":["Windows Service"]}},"agent":{"id":"004","name":"win-dc-01"},"manager":{"name":"wazuh-manager"},"decoder":{"name":"windows_eventchannel"},"location":"EventChannel","id":"1694607138.3688437"}"#;
        let row = Row::parse(line).unwrap();
        assert_eq!(row.rule_id, 110011);
        assert_eq!(row.rule_level, 12);
        assert_eq!(row.agent_name, "win-dc-01");
        assert_eq!(
            row.mitre_tactics,
            vec!["Persistence", "Privilege Escalation"]
        );
        assert_eq!(row.raw, line);
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        let row = Row::parse(r#"{"timestamp":"2026-08-18T00:00:00.000+0000"}"#).unwrap();
        assert_eq!(row.rule_id, 0);
        assert!(row.agent_id.is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Row::parse("not json").is_err());
    }

    #[test]
    fn parses_vulnerability_detector_alert() {
        let line = r#"{"timestamp":"2026-08-18T10:00:00.000+0000","rule":{"level":10,"description":"CVE-2024-6387 affects openssh-server","id":"23505","groups":["vulnerability-detector"]},"agent":{"id":"002","name":"db-01"},"manager":{"name":"wazuh-manager"},"location":"vulnerability-detector","data":{"vulnerability":{"cve":"CVE-2024-6387","severity":"Critical","status":"Active","package":{"name":"openssh-server","version":"9.2p1"},"cvss":{"cvss3":{"base_score":"8.1"}}}},"id":"1.9"}"#;
        let row = Row::parse(line).unwrap();
        assert_eq!(row.vuln_cve, "CVE-2024-6387");
        assert_eq!(row.vuln_severity, "Critical");
        assert_eq!(row.vuln_package, "openssh-server");
        assert_eq!(row.vuln_package_version, "9.2p1");
        assert_eq!(row.vuln_status, "Active");
        assert!((row.vuln_score - 8.1).abs() < 0.001);
    }

    #[test]
    fn vulnerability_fields_empty_for_regular_alerts() {
        let row = Row::parse(r#"{"timestamp":"2026-08-18T00:00:00.000+0000"}"#).unwrap();
        assert!(row.vuln_cve.is_empty());
        assert_eq!(row.vuln_score, 0.0);
    }
}
