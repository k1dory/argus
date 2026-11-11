#!/usr/bin/env bash
# Резервная копия: BACKUP DATABASE argus на диск backups + тома web-auth
# (единственная копия пользователей/паролей/TOTP консоли — шифруется),
# shipper-state и collector-state (содержит сырые события — шифруется).
# Каталог — BACKUP_DIR (по умолчанию /var/backups/argus, вне
# дерева проекта), ротация — BACKUP_KEEP_DAYS (14).
# Место: бэкап не съедает диск под ClickHouse. До BACKUP и до копирования
# архива на диске должно остаться BACKUP_RESERVE_MB (10240) сверх нужного;
# не хватает — удаляются самые старые полные наборы (последний остаётся),
# всё ещё не хватает — отказ до записи. При любом сбое недописанный архив и
# копия на диске backups ClickHouse удаляются (на полном диске — по пути тома,
# `docker compose exec` там уже не запускается).
# Переменные окружения сильнее .env: так роль задаёт ротацию из инвентаря.
#   ./scripts/backup.sh            → $BACKUP_DIR/argus-<UTC>.zip, *-web-auth.tar.gz.{age|enc}, *-shipper-state.tar.gz
#   ./scripts/restore.sh <name>    → восстановление
# Шифрование web-auth: age (BACKUP_AGE_RECIPIENT=age1…) или, если age нет,
# openssl enc -aes-256-cbc -pbkdf2 с ключом BACKUP_KEY. Без ключа — отказ.
# Пароль ClickHouse в URL/argv не попадает: clickhouse-client внутри контейнера
# читает CLICKHOUSE_PASSWORD из окружения (порт 8123 наружу не публикуется).
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
ENV_KEEP="${BACKUP_KEEP_DAYS-}" ENV_RESERVE="${BACKUP_RESERVE_MB-}" ENV_DIR="${BACKUP_DIR-}"
[ -f .env ] && set -a && . ./.env && set +a
[ -n "$ENV_KEEP" ] && BACKUP_KEEP_DAYS="$ENV_KEEP"
[ -n "$ENV_RESERVE" ] && BACKUP_RESERVE_MB="$ENV_RESERVE"
[ -n "$ENV_DIR" ] && BACKUP_DIR="$ENV_DIR"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/argus}"
KEEP="${BACKUP_KEEP_DAYS:-14}"
RESERVE_MB="${BACKUP_RESERVE_MB:-10240}"
for v in KEEP RESERVE_MB; do
  case "${!v}" in ''|*[!0-9]*) echo "backup: $v=${!v} — нужно целое число" >&2; exit 1 ;; esac
done
RESERVE=$((RESERVE_MB * 1024 * 1024))
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

PROJECT="$(docker compose config --format json | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")"

say_err() {
  echo "backup: $*" >&2
  command -v logger >/dev/null 2>&1 && logger -t argus-backup -p user.err -- "$*" || true
}

# Копию на диске backups ClickHouse и недописанные файлы этого запуска убираем
# при любом выходе до «готово»: иначе они копятся (11.11.2026 на argus1 — 34 ГБ
# и полный диск). Сначала по пути тома на хосте: unlink места не требует, а
# `docker compose exec` на полном диске падает (runc пишет во /tmp).
CH_ARCHIVE="/var/lib/clickhouse/backups/$NAME.zip"
DONE=0
rm_staging() {
  local mp
  mp="$(docker volume inspect -f '{{.Mountpoint}}' "${PROJECT}_clickhouse-backups" 2>/dev/null || true)"
  [ -n "$mp" ] && rm -f -- "$mp/$NAME.zip" 2>/dev/null
  docker compose exec -T clickhouse rm -f "$CH_ARCHIVE" >/dev/null 2>&1 || true
}
on_exit() {
  local rc=$?
  rm_staging
  if [ "$DONE" != 1 ]; then
    rm -f -- "$BACKUP_DIR/$NAME.zip" "$BACKUP_DIR/$NAME"-*
    say_err "сбой (код $rc), набор $NAME не создан, недописанные файлы удалены"
  fi
}
trap on_exit EXIT

avail_dir() { # свободно в каталоге, байт
  df -Pk -- "$1" | awk 'NR==2 {print $4 * 1024}'
}
avail_staging() { # свободно на диске backups ClickHouse, байт
  q "SELECT free_space FROM system.disks WHERE name = 'backups'"
}
# Полные наборы (есть .zip), старые первыми; текущий запуск не входит.
old_sets() {
  local f
  for f in "$BACKUP_DIR"/argus-*.zip; do
    [ -e "$f" ] || continue
    f="${f##*/}"; f="${f%.zip}"
    [ "$f" = "$NAME" ] || echo "$f"
  done | sort
}
# need байт + резерв: удаляем старые наборы, пока не влезет; последний не трогаем.
ensure_space() { # need, функция-измеритель, её аргумент, что пишем
  local need=$1 probe=$2 arg=$3 what=$4 have oldest
  while :; do
    have="$($probe "$arg" || true)"
    case "$have" in ''|*[!0-9]*) say_err "$what: не удалось узнать свободное место ($have)"; return 1 ;; esac
    [ "$have" -ge $((need + RESERVE)) ] && return 0
    if [ "$(old_sets | wc -l)" -le 1 ]; then
      say_err "$what: нужно $((need / 1048576)) МБ + резерв $RESERVE_MB МБ, свободно $((have / 1048576)) МБ; удалять больше нечего (последний набор оставлен)"
      return 1
    fi
    oldest="$(old_sets | head -n1)"
    echo "мало места ($what): удаляю старый набор $oldest"
    rm -f -- "$BACKUP_DIR/$oldest.zip" "$BACKUP_DIR/$oldest"-*
  done
}

echo "backup clickhouse → $NAME.zip"
# Оценка архива — размер активных кусков базы (архив не больше: куски уже сжаты).
EST="$(q "SELECT sum(bytes_on_disk) FROM system.parts WHERE database = 'argus' AND active")"
case "$EST" in ''|*[!0-9]*) say_err "не удалось оценить размер базы ($EST)"; exit 1 ;; esac
ensure_space "$EST" avail_staging - "диск backups ClickHouse"
q "BACKUP DATABASE argus TO Disk('backups', '$NAME.zip')" >/dev/null
SIZE="$(docker compose exec -T clickhouse stat -c %s "$CH_ARCHIVE")"
ensure_space "$SIZE" avail_dir "$BACKUP_DIR" "$BACKUP_DIR"
docker compose cp "clickhouse:$CH_ARCHIVE" "$BACKUP_DIR/$NAME.zip"
q "SYSTEM UNFREEZE" >/dev/null 2>&1 || true
rm_staging

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
DONE=1
echo "готово: $NAME"
