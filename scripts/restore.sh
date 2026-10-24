#!/usr/bin/env bash
# Восстановление из $BACKUP_DIR/<name>.zip (+ тома):
#   ./scripts/restore.sh argus-20260906T100000Z
# web-auth расшифровывается age (BACKUP_AGE_IDENTITY=/path/key.txt) или
# openssl с BACKUP_KEY — тем же способом, каким шифровал backup.sh.
# До запуска остановите collector, engine, web и shipper: том очереди нельзя
# заменять, пока коллектор держит в памяти ссылки на его файлы.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ -f .env ] && set -a && . ./.env && set +a
BACKUP_DIR="${BACKUP_DIR:-/var/backups/argus}"
NAME="${1:?имя бэкапа, например argus-20260906T100000Z}"
ALPINE="${REGISTRY_MIRROR:-docker.io}/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
[ -f "$BACKUP_DIR/$NAME.zip" ] || { echo "restore: нет $BACKUP_DIR/$NAME.zip" >&2; exit 1; }

export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD не задан (.env)}"
q() { docker compose exec -T -e CLICKHOUSE_PASSWORD clickhouse clickhouse-client --user "${CLICKHOUSE_USER:-argus}" --query "$1"; }

docker compose cp "$BACKUP_DIR/$NAME.zip" "clickhouse:/var/lib/clickhouse/backups/$NAME.zip"
echo "restore clickhouse ← $NAME.zip (существующие таблицы будут заменены)"
q "RESTORE DATABASE argus FROM Disk('backups', '$NAME.zip') SETTINGS allow_non_empty_tables=true" >/dev/null
docker compose exec -T clickhouse rm -f "/var/lib/clickhouse/backups/$NAME.zip"

PROJECT="$(docker compose config --format json | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")"
untarvol() { # имя тома ← tar.gz из stdin
  docker run --rm -i -v "${PROJECT}_$1:/v" "$ALPINE" sh -c 'rm -rf /v/* /v/..?* /v/.[!.]* 2>/dev/null; tar xzf - -C /v'
}

if [ -f "$BACKUP_DIR/$NAME-web-auth.tar.gz.age" ]; then
  [ -n "${BACKUP_AGE_IDENTITY:-}" ] || { echo "restore: нужен BACKUP_AGE_IDENTITY (файл ключа age)" >&2; exit 1; }
  age -d -i "$BACKUP_AGE_IDENTITY" "$BACKUP_DIR/$NAME-web-auth.tar.gz.age" | untarvol web-auth
  echo "volume web-auth восстановлен (age)"
elif [ -f "$BACKUP_DIR/$NAME-web-auth.tar.gz.enc" ]; then
  [ -n "${BACKUP_KEY:-}" ] || { echo "restore: нужен BACKUP_KEY" >&2; exit 1; }
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY -in "$BACKUP_DIR/$NAME-web-auth.tar.gz.enc" | untarvol web-auth
  echo "volume web-auth восстановлен (openssl)"
elif [ -f "$BACKUP_DIR/$NAME-web-auth.tar.gz" ]; then
  untarvol web-auth <"$BACKUP_DIR/$NAME-web-auth.tar.gz"
  echo "volume web-auth восстановлен (старый незашифрованный формат)"
fi
if [ -f "$BACKUP_DIR/$NAME-shipper-state.tar.gz" ]; then
  untarvol shipper-state <"$BACKUP_DIR/$NAME-shipper-state.tar.gz"
  docker run --rm -v "${PROJECT}_shipper-state:/v" "$ALPINE" chown -R 65532:65532 /v
  echo "volume shipper-state восстановлен"
fi
if [ -f "$BACKUP_DIR/$NAME-collector-state.tar.gz.age" ]; then
  [ -n "${BACKUP_AGE_IDENTITY:-}" ] || { echo "restore: нужен BACKUP_AGE_IDENTITY (файл ключа age)" >&2; exit 1; }
  age -d -i "$BACKUP_AGE_IDENTITY" "$BACKUP_DIR/$NAME-collector-state.tar.gz.age" | untarvol collector-state
  docker run --rm -v "${PROJECT}_collector-state:/v" "$ALPINE" chown -R 65532:65532 /v
  echo "volume collector-state восстановлен (age)"
elif [ -f "$BACKUP_DIR/$NAME-collector-state.tar.gz.enc" ]; then
  [ -n "${BACKUP_KEY:-}" ] || { echo "restore: нужен BACKUP_KEY" >&2; exit 1; }
  openssl enc -d -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY -in "$BACKUP_DIR/$NAME-collector-state.tar.gz.enc" | untarvol collector-state
  docker run --rm -v "${PROJECT}_collector-state:/v" "$ALPINE" chown -R 65532:65532 /v
  echo "volume collector-state восстановлен (openssl)"
fi
echo "готово; перезапустите web, shipper и collector: docker compose restart web shipper collector"
