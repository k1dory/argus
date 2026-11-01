- **`engine dataset export` / `engine dataset eval` — датасет и замеры моделей решений.** Выгрузка
  в JSONL (`argus-dataset/v1`) инцидентов, которые завершил человек с меткой (`labeled_by_human`),
  с обезличенным состоянием, `group_id` случая, разбиением train/holdout (25 % по группе) и
  потолком записей на правило (`--max-per-rule`, по умолчанию 100). По флагу `--models laya,jev`
  тем же вопросам отвечают модели System One: `laya-serve` (`ARGUS_LAYA_ENDPOINT`,
  `ARGUS_LAYA_MODEL`, `ARGUS_LAYA_TOKEN`) и Jev (`ARGUS_JEV_ENABLED=1`, `ARGUS_JEV_API_KEY`,
  `ARGUS_JEV_ENDPOINT`, `ARGUS_JEV_MODEL`). Инциденты с ПДн в Jev не отправляются никогда.
  `eval` считает acc, soft acc, Brier, ECE, NLL по слепой части holdout, подбирает температуру
  и пороги автозакрытия и подсказки на train. Без флага `--models` внешние вызовы не делаются.
  Миграций нет. ML-часть проекта — https://huggingface.co/k1dory/laya-argus.
