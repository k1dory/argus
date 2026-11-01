- **Правила: техники ATT&CK v20 сверены с тактиками.** `proxy-foreign-access` получил
  технику (T1595 Active Scanning). Сканы снаружи (`net-inbound-portscan`,
  `fw-inbound-deny-burst`) — T1595 вместо T1046 (Network Service Discovery относится к
  разведке изнутри, тактика discovery). Молчание агента Wazuh — T1685 Disable or Modify
  Tools (Defense Impairment) вместо T1489 Service Stop (Impact). У `waf-rce-critical` —
  тактика initial access к T1190. Новый тест следит, чтобы техника правила относилась к
  его тактике и чтобы у каждого правила ИБ была техника.
