#!/usr/bin/env bash
# Резервная копия: BACKUP DATABASE argus на диск backups + тома web-auth
# (единственная копия пользователей/паролей/TOTP консоли — шифруется),
# shipper-state и collector-state (содержит сырые события — шифруется).
# Каталог — BACKUP_DIR (по умолчанию /var/backups/argus, вне
# дерева проекта), ротация — BACKUP_KEEP_DAYS (14).
#   ./scripts/backup.sh            → $BACKUP_DIR/argus-<UTC>.zip, *-web-auth.tar.gz.{age|enc}, *-shipper-state.tar.gz
#   ./scripts/restore.sh <name>    → восстановление
# Шифрование web-auth: age (BACKUP_AGE_RECIPIENT=age1…) или, если age нет,
# openssl enc -aes-256-cbc -pbkdf2 с ключом BACKUP_KEY. Без ключа — отказ.
# Пароль ClickHouse в URL/argv не попадает: clickhouse-client внутри контейнера
# читает CLICKHOUSE_PASSWORD из окружения (порт 8123 наружу не публикуется).
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ -f .env ] && set -a && . ./.env && set +a
BACKUP_DIR="${BACKUP_DIR:-/var/backups/argus}"
KEEP="${BACKUP_KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="argus-$STAMP"
ALPINE="${REGISTRY_MIRROR:-docker.io}/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

# Способ шифрования выбираем до начала работы, чтобы не оставить открытый архив.
if command -v age >/dev/null 2>&1 && [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
  enc() { age -r "$BACKUP_AGE_RECIPIENT" -o "$1.age"; }
  EXT=age
elif [ -n "${BACKUP_KEY:-}" ]; then
  enc() { openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_KEY -out "$1.enc"; }
  EXT=enc
else
  echo "backup: нет ключа шифрования — задайте BACKUP_AGE_RECIPIENT (age) или BACKUP_KEY (openssl) в .env" >&2
  exit 1
fi

# Права 700 — только на каталог, созданный нами: чужой (например, общий
# /var/backups с другими владельцами) не трогаем.
if [ ! -d "$BACKUP_DIR" ]; then
  mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
fi
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD не задан (.env)}"
q() { docker compose exec -T -e CLICKHOUSE_PASSWORD clickhouse clickhouse-client --user "${CLICKHOUSE_USER:-argus}" --query "$1"; }

# Архив на диске backups ClickHouse убираем и при обрыве (Ctrl-C, ошибка cp):
# иначе он копится в томе clickhouse-backups до следующего запуска.
CH_ARCHIVE="/var/lib/clickhouse/backups/$NAME.zip"
cleanup_ch() {
  docker compose exec -T clickhouse rm -f "$CH_ARCHIVE" >/dev/null 2>&1 || true
}
trap cleanup_ch EXIT

echo "backup clickhouse → $NAME.zip"
q "BACKUP DATABASE argus TO Disk('backups', '$NAME.zip')" >/dev/null
docker compose cp "clickhouse:$CH_ARCHIVE" "$BACKUP_DIR/$NAME.zip"
q "SYSTEM UNFREEZE" >/dev/null 2>&1 || true
cleanup_ch

PROJECT="$(docker compose config --format json | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")"
tarvol() { # имя тома → tar.gz в stdout
  docker run --rm -v "${PROJECT}_$1:/v:ro" "$ALPINE" tar czf - -C /v .
}
echo "backup volume web-auth (шифрование: $EXT)"
tarvol web-auth | enc "$BACKUP_DIR/$NAME-web-auth.tar.gz"
echo "backup volume shipper-state"
tarvol shipper-state >"$BACKUP_DIR/$NAME-shipper-state.tar.gz"
echo "backup volume collector-state (шифрование: $EXT)"
tarvol collector-state | enc "$BACKUP_DIR/$NAME-collector-state.tar.gz"

echo "ротация: старше $KEEP дней"
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'argus-*' -mtime +"$KEEP" -delete
for f in "$BACKUP_DIR/$NAME"*; do ls -la "$f"; done
echo "готово: $NAME"
