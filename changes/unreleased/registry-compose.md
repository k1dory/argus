- **Образ engine собирается из корня репозитория, и реестр поставляемого набора есть в любой
  сборке (ревью codex #73).** `engine/Dockerfile` копирует `rules/` и `fixtures/events/`, корневой
  `.dockerignore` пропускает только `engine/`, `rules/` и `fixtures/events/`. Теперь
  `make up`/`up-dev`, compose и режим ansible `argus_images: build` дают образ с реестром, в том
  числе без buildx (classic builder). Вместо именованных контекстов `rules`/`fixtures` в
  `release.yml` для engine используется `context: .`. Вручную: `docker build -f engine/Dockerfile .`.
- **Реестр не загружается без фикстур.** Если каталога фикстур нет или в нём нет событий с
  `source` и `action`, загрузка падает. Значения из селекторов правил не считаются полным словарём.
  `engine dataset export` в таком случае завершается с кодом 2, не обращаясь к ClickHouse и не
  трогая `--out`.
