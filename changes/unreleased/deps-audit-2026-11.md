- **Зависимости: quinn-udp 0.5.16, обновления web без мажорных версий.** `quinn-udp`
  закрывает RUSTSEC-2026-0538 (шиппер). В web — `npm audit fix` без `--force`; `shadcn`
  перенесён в devDependencies: из него при сборке берётся только `shadcn/tailwind.css`,
  в standalone-образ он не попадает (`npm audit --omit=dev` — 0 уязвимостей).
