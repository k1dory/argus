- **Несовместимо: формат строк объявляет источник, error-лог ModSecurity больше не источник
  WAF.** Разборщик CEF, LEEF и Coraza выбирается по объявлению — `SYSLOG_PEER_FORMAT`
  («адрес|CIDR=cef|leef|waf-coraza»), `files[].format` (`waf-audit`, `waf-coraza`, `lines`) или
  SD-параметр агента `[argus format="…"]`, — а не по содержимому строки: «CEF:», «LEEF:»,
  «Coraza:» в данных (имя файла, User-Agent) больше не меняют разборщик. Строки
  `ModSecurity: …` из error-лога nginx/Apache — обычный syslog с `attrs.waf_unparsed=1`, без
  `http.attack`, `rule_ids` и решения: их `msg`/`uri` не экранированы и подделываются запросом.
  **Перед обновлением:** ModSecurity — включите `SecAuditLogFormat JSON` и шлите audit-лог
  (`WAF_AUDIT_LOG` или `POST /ingest/modsecurity`); NGFW/EDR с CEF/LEEF — объявите адреса в
  `SYSLOG_PEER_FORMAT`; агент Coraza — сначала обновите агент (`format="waf-coraza"` в SD), потом
  коллектор. В этом релизе необъявленные строки, похожие на CEF/LEEF/WAF, видны в журнале
  коллектора («необъявленный формат») и в `argus_collector_undeclared_format_total`.
