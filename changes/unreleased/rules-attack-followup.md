### Правила

- `proxy-foreign-access` (a41c-net-076): T1595 заменён на `attack.initial_access` + T1078 (Valid Accounts) — успешные обращения из чужой страны сканом не являются.
- `fw-inbound-deny-burst` (a41c-net-073): источники из частных и служебных диапазонов (RFC 1918, loopback, link-local, ULA) исключены — скан изнутри это T1046 (Discovery), а не Active Scanning снаружи.
- Guard-тест техник ATT&CK собирает правила как `rules.Files` в engine: `.yml` и `.yaml`, каталоги `tests` пропускаются на любом уровне.
