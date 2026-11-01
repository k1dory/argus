- **Датасет `argus-dataset/v2` — вопросы по форме закрытия из плана разметки (миграция 0036).**
  ИБ: `disposition`, `escalate`, `severity_level` (Score 1–4), `attack_tactic` (15 тактик ATT&CK
  v20 + «другое»), `attack_technique` (кандидаты + «другое»). DevOps: `ops_cause` (8 причин),
  `ops_act_now`, `ops_urgency` (Score 1–4). `severity_correct` и `ops_action` больше не спрашиваются.
  Технику модели выбирают вторым запросом: кандидаты строятся по тактике, которую ответила сама модель,
  а не человек. Те же кандидаты, что видел аналитик, пишутся в запись для обучения. Метка ATT&CK
  другой версии справочника в запись не берётся. Записи v1 `engine dataset eval` не читает.
- **`attack.Candidates` / `attack.DefaultTactic` в движке — порт подбора кандидатов техники из
  консоли.** Обе реализации сверяются с одним эталоном `testdata/attack-candidates.json`
  (`TestCandidatesGolden` и `web/tests/attack-candidates.test.ts`).
