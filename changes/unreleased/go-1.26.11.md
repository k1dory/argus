- **Go 1.26.11 в образах collector, engine, mcp, policyd.** Закрывает CVE-2026-97054
  (stdlib, HTTP/1-сервер при превышении лимита MaxBytesReader); на 1.26.10 Trivy
  останавливал сборку релиза rc37, образы rc37 не опубликованы — rc38 их заменяет.
