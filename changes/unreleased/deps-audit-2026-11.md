- **Зависимости: quinn-udp 0.5.16, обновления web без мажорных версий прямых зависимостей.** `quinn-udp`
  закрывает RUSTSEC-2026-0538 (шиппер). В web — `npm audit fix` без `--force` (транзитивно minimatch 10 → 11 для typescript-eslint, next 16.4.3 → 16.4.6); `shadcn`
  перенесён в devDependencies: из него при сборке берётся только `shadcn/tailwind.css`,
  в standalone-образ он не попадает (`npm audit --omit=dev` — 0 уязвимостей).
- **CI: блокирующий `npm audit` — по зависимостям образа (`--omit=dev`).** Для picomatch
  (ReDoS, все версии до 4.0.7; тянут eslint и shadcn CLI) исправленного выпуска нет, в
  standalone-образ он не попадает. Полный аудит остаётся информационным шагом.
