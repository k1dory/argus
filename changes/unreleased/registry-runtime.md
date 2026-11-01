- **Реестр поставляемого набора теперь читается при запуске, `shipped.json` удалён.** Образ движка
  несёт копию `rules/` и `fixtures/events` своей версии в `/usr/share/argus/shipped`. Их передают
  именованные контексты `rules` и `fixtures` в `release.yml`; вручную — `docker buildx build
  --build-context rules=./rules --build-context fixtures=./fixtures/events ./engine`.
  `engine dataset export` читает реестр оттуда (`ARGUS_SHIPPED_DIR`) и отказывает, если копии нет.
  `RULES_DIR` не используется: там бывают пользовательские правила. Перегенерировать реестр при
  правке правил или фикстур больше не нужно. Без контекстов (classic builder) образ собирается
  как раньше, но выгрузка датасета на нём не запускается. CI (job `compose`) проверяет, что копия
  есть в образе.
