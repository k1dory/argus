#!/usr/bin/env bash
# Резервная копия: BACKUP DATABASE argus на диск backups + тома web-auth
# (единственная копия пользователей/паролей/TOTP консоли — шифруется),
# shipper-state и collector-state (содержит сырые события — шифруется).
# Каталог — BACKUP_DIR (по умолчанию /var/backups/argus, вне
# дерева проекта), ротация — BACKUP_KEEP_DAYS (14).
#   ./scripts/backup.sh            → $BACKUP_DIR/argus-<UTC>.zip, *-web-auth.tar.gz.{age|enc}, *-shipper-state.tar.gz,
#                                    *-collector-state.tar.gz.{age|enc}, argus-<UTC>.complete — признак полного набора
#   ./scripts/restore.sh <name>    → восстановление
# Шифрование web-auth: age (BACKUP_AGE_RECIPIENT=age1…) или, если age нет,
# openssl enc -aes-256-cbc -pbkdf2 с ключом BACKUP_KEY. Без ключа — отказ.
# Пароль ClickHouse в URL/argv не попадает: clickhouse-client внутри контейнера
# читает CLICKHOUSE_PASSWORD из окружения (порт 8123 наружу не публикуется).
#
# Место (11.11.2026 полные копии за 14 дней заполнили диск argus1, ClickHouse
# встал): перед каждой записью — BACKUP, копированием архива и каждым томом —
# на диске должно остаться BACKUP_RESERVE_MB (10240) сверх нужного. Не хватает —
# удаляются сначала неполные наборы, затем самые старые полные; последний полный
# не удаляется никогда, в том числе ротацией. Всё ещё не хватает — отказ до
# записи, причина в stderr и syslog (тег argus-backup). Наборы удаляются только
# на том диске, место на котором нужно освободить.
# При любом сбое файлы этого запуска и копия на диске backups ClickHouse
# удаляются: копия — по пути тома на хосте (unlink места не требует, а
# `docker compose exec` на полном диске не запускается), затем через exec.
# Удаляются только файлы со строгим именем набора argus-<UTC>…; признак полноты —
# argus-<UTC>.complete (у наборов до него — все четыре файла).
# Непустые BACKUP_KEEP_DAYS / BACKUP_RESERVE_MB / BACKUP_DIR из окружения сильнее
# .env (так роль задаёт их из инвентаря); пустое значение = не задано.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
ENV_KEEP="${BACKUP_KEEP_DAYS-}" ENV_RESERVE="${BACKUP_RESERVE_MB-}" ENV_DIR="${BACKUP_DIR-}"
[ -f .env ] && set -a && . ./.env && set +a
[ -n "$ENV_KEEP" ] && BACKUP_KEEP_DAYS="$ENV_KEEP"
[ -n "$ENV_RESERVE" ] && BACKUP_RESERVE_MB="$ENV_RESERVE"
[ -n "$ENV_DIR" ] && BACKUP_DIR="$ENV_DIR"

num() { # имя, значение, минимум, максимум → десятичное число (ведущие нули — не восьмеричные)
  local v="$2"
  if [[ ! $v =~ ^[0-9]{1,9}$ ]] || (( 10#$v < $3 || 10#$v > $4 )); then
    echo "backup: $1=$v — нужно целое число $3…$4" >&2
    return 1
  fi
  echo $((10#$v))
}
BACKUP_DIR="${BACKUP_DIR:-/var/backups/argus}"
KEEP="$(num BACKUP_KEEP_DAYS "${BACKUP_KEEP_DAYS:-14}" 1 9999)"
RESERVE_MB="$(num BACKUP_RESERVE_MB "${BACKUP_RESERVE_MB:-10240}" 0 9999999)"
RESERVE=$((RESERVE_MB * 1048576))
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="argus-$STAMP"
ALPINE="${REGISTRY_MIRROR:-docker.io}/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
# Файлы набора — только такие имена; всё прочее в каталоге скрипт не трогает.
SET_RE='^(argus-[0-9]{8}T[0-9]{6}Z)(\.zip|\.complete|-web-auth\.tar\.gz(\.enc|\.age)?|-shipper-state\.tar\.gz|-collector-state\.tar\.gz\.(enc|age))$'
SET_SUFFIXES=".zip .complete -web-auth.tar.gz -web-auth.tar.gz.enc -web-auth.tar.gz.age -shipper-state.tar.gz -collector-state.tar.gz.enc -collector-state.tar.gz.age"

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
# Один запуск за раз: параллельный увидел бы чужой незавершённый набор как мусор.
if command -v flock >/dev/null 2>&1; then
  exec 9>>"$BACKUP_DIR/.backup.lock"
  flock -n 9 || { echo "backup: уже идёт другой запуск ($BACKUP_DIR/.backup.lock)" >&2; exit 1; }
fi
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:?CLICKHOUSE_PASSWORD не задан (.env)}"
q() { docker compose exec -T -e CLICKHOUSE_PASSWORD clickhouse clickhouse-client --user "${CLICKHOUSE_USER:-argus}" --query "$1"; }

PROJECT="$(docker compose config --format json | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")"

say_err() {
  echo "backup: $*" >&2
  if command -v logger >/dev/null 2>&1; then logger -t argus-backup -p user.err -- "$*" || true; fi
}

# Каталог тома clickhouse-backups на хосте: каталог-источник (init-storage.sh) или
# точка монтирования тома. Узнаём до записи — при сбое docker может уже не ответить.
STAGING_HOST="$(docker volume inspect -f '{{with .Options}}{{index . "device"}}{{end}}' "${PROJECT}_clickhouse-backups" 2>/dev/null || true)"
[ -n "$STAGING_HOST" ] || STAGING_HOST="$(docker volume inspect -f '{{.Mountpoint}}' "${PROJECT}_clickhouse-backups" 2>/dev/null || true)"
[ -n "$STAGING_HOST" ] && [ -d "$STAGING_HOST" ] || STAGING_HOST=""

# Запуск в ту же секунду получил бы то же имя, и его уборка удалила бы чужие файлы.
for f in "$BACKUP_DIR/$NAME".* "$BACKUP_DIR/$NAME"-* ${STAGING_HOST:+"$STAGING_HOST/$NAME.zip"}; do
  if [ -e "$f" ]; then echo "backup: $f уже существует — повторный запуск в ту же секунду, отказ" >&2; exit 1; fi
done

# Уборка при любом выходе до признака полноты: только то, что создал этот запуск.
CH_ARCHIVE="/var/lib/clickhouse/backups/$NAME.zip"
CREATED=()
STAGED=0
DONE=0
rm_staging() {
  if [ -n "$STAGING_HOST" ]; then rm -f -- "$STAGING_HOST/$NAME.zip" || true; fi
  docker compose exec -T clickhouse rm -f "$CH_ARCHIVE" >/dev/null 2>&1 || true
  if [ -n "$STAGING_HOST" ] && [ -e "$STAGING_HOST/$NAME.zip" ]; then
    say_err "не удалось удалить $STAGING_HOST/$NAME.zip — уберите вручную"
  fi
}
on_exit() {
  local rc=$? f
  set +e
  [ "$STAGED" = 1 ] && rm_staging
  if [ "$DONE" != 1 ]; then
    for f in ${CREATED[@]+"${CREATED[@]}"}; do
      rm -f -- "$f" || say_err "не удалось удалить $f"
    done
    say_err "сбой (код $rc): набор $NAME не создан, файлы этого запуска удалены"
    [ "$rc" = 0 ] && rc=1
  fi
  exit "$rc"
}
trap on_exit EXIT

# ── Место ────────────────────────────────────────────────────────────────────
avail_dir() { # свободно в каталоге, байт; KiB из df без арифметики awk (mawk печатает 1e+11)
  local kb
  kb="$(df -Pk -- "$1" | awk 'NR==2 {print $4}')"
  [[ $kb =~ ^[0-9]+$ ]] || return 1
  echo $((kb * 1024))
}
avail_staging() { # свободно на диске backups ClickHouse за вычетом его резервирований, байт
  q "SELECT unreserved_space FROM system.disks WHERE name = 'backups'"
}
dev_of() { stat -c %d -- "$1" 2>/dev/null || stat -f %d -- "$1"; }
SAME_FS=0
if [ -n "$STAGING_HOST" ] && [ "$(dev_of "$STAGING_HOST")" = "$(dev_of "$BACKUP_DIR")" ]; then SAME_FS=1; fi

is_complete() { # набор: признак или (старый формат) все четыре файла
  local b="$BACKUP_DIR/$1"
  [ -e "$b.complete" ] && return 0
  [ -e "$b.zip" ] && [ -e "$b-shipper-state.tar.gz" ] &&
    { [ -e "$b-web-auth.tar.gz.enc" ] || [ -e "$b-web-auth.tar.gz.age" ] || [ -e "$b-web-auth.tar.gz" ]; } &&
    { [ -e "$b-collector-state.tar.gz.enc" ] || [ -e "$b-collector-state.tar.gz.age" ]; }
}
scan_sets() { # → ALL_SETS, COMPLETE_SETS по возрастанию времени, без текущего запуска
  local f b s seen=" "
  ALL_SETS=(); COMPLETE_SETS=()
  for f in "$BACKUP_DIR"/argus-*; do
    b="${f##*/}"
    [[ $b =~ $SET_RE ]] || continue
    s="${BASH_REMATCH[1]}"
    [ "$s" = "$NAME" ] && continue
    case "$seen" in *" $s "*) continue ;; esac
    seen="$seen$s "
    ALL_SETS+=("$s")
    if is_complete "$s"; then COMPLETE_SETS+=("$s"); fi
  done
}
delete_set() {
  local x
  for x in $SET_SUFFIXES; do rm -f -- "$BACKUP_DIR/$1$x"; done
}
# Кого удалить ради места: сначала неполные наборы, затем старейший полный — но не последний полный.
prune_victim() {
  local s n
  scan_sets
  for s in ${ALL_SETS[@]+"${ALL_SETS[@]}"}; do
    if ! is_complete "$s"; then echo "$s"; return; fi
  done
  n=${#COMPLETE_SETS[@]}
  if [ "$n" -gt 1 ]; then echo "${COMPLETE_SETS[0]}"; fi
}
ensure_space() { # нужно байт, измеритель, его аргумент, что пишем, можно ли удалять наборы (0/1)
  local need=$1 probe=$2 arg=$3 what=$4 prune=$5 have victim
  while :; do
    have="$($probe "$arg" || true)"
    if [[ ! $have =~ ^[0-9]+$ ]]; then say_err "$what: не удалось узнать свободное место ($have)"; return 1; fi
    if (( have >= need + RESERVE )); then return 0; fi
    victim=""
    if [ "$prune" = 1 ]; then victim="$(prune_victim)"; fi
    if [ -z "$victim" ]; then
      say_err "$what: нужно $((need / 1048576)) МБ + резерв $RESERVE_MB МБ, свободно $((have / 1048576)) МБ; $( [ "$prune" = 1 ] && echo 'удалять больше нечего (последний полный набор оставлен)' || echo 'наборы лежат на другом диске, их удаление не поможет')"
      return 1
    fi
    echo "мало места ($what): удаляю набор $victim"
    delete_set "$victim"
  done
}
num_or_fail() { [[ $2 =~ ^[0-9]+$ ]] || { say_err "$1: не число ($2)"; return 1; }; echo "$2"; }
vol_bytes() { # оценка архива тома: размер содержимого + 1 МиБ на tar/gzip/шифрование
  local kb
  kb="$(docker run --rm -v "${PROJECT}_$1:/v:ro" "$ALPINE" du -sk /v | awk 'NR==1 {print $1}')"
  num_or_fail "оценка тома $1" "$kb" >/dev/null || return 1
  echo $((kb * 1024 + 1048576))
}

# Оценка архива: активные куски базы + 10% и 16 МиБ на метаданные бэкапа и
# вставки между оценкой и снимком.
DB="$(num_or_fail "оценка базы" "$(q "SELECT sum(bytes_on_disk) FROM system.parts WHERE database = 'argus' AND active")")"
EST=$((DB + DB / 10 + 16777216))
VOLS=0
for v in web-auth shipper-state collector-state; do
  b="$(vol_bytes "$v")"
  VOLS=$((VOLS + b))
done
if [ "$SAME_FS" = 1 ]; then
  # Один диск: на пике лежат копия на диске backups и её копия в BACKUP_DIR.
  ensure_space $((EST * 2 + VOLS)) avail_dir "$BACKUP_DIR" "$BACKUP_DIR (с диском backups)" 1
else
  ensure_space "$EST" avail_staging - "диск backups ClickHouse" 0
  ensure_space $((EST + VOLS)) avail_dir "$BACKUP_DIR" "$BACKUP_DIR" 1
fi

# ── Запись ───────────────────────────────────────────────────────────────────
echo "backup clickhouse → $NAME.zip"
STAGED=1
q "BACKUP DATABASE argus TO Disk('backups', '$NAME.zip')" >/dev/null
SIZE="$(docker compose exec -T clickhouse stat -c %s "$CH_ARCHIVE" || true)"
if [[ ! $SIZE =~ ^[0-9]+$ ]] && [ -n "$STAGING_HOST" ]; then SIZE="$(wc -c <"$STAGING_HOST/$NAME.zip" | tr -d ' ')"; fi
SIZE="$(num_or_fail "размер архива" "$SIZE")"
ensure_space $((SIZE + VOLS)) avail_dir "$BACKUP_DIR" "$BACKUP_DIR" 1
CREATED+=("$BACKUP_DIR/$NAME.zip")
docker compose cp "clickhouse:$CH_ARCHIVE" "$BACKUP_DIR/$NAME.zip"
q "SYSTEM UNFREEZE" >/dev/null 2>&1 || true
rm_staging
STAGED=0

tarvol() { # имя тома → tar.gz в stdout
  docker run --rm -v "${PROJECT}_$1:/v:ro" "$ALPINE" tar czf - -C /v .
}
volume() { # имя тома, шифровать ли (1/0)
  local out="$BACKUP_DIR/$NAME-$1.tar.gz" need
  need="$(vol_bytes "$1")"
  ensure_space "$need" avail_dir "$BACKUP_DIR" "$BACKUP_DIR (том $1)" 1
  if [ "$2" = 1 ]; then
    echo "backup volume $1 (шифрование: $EXT)"
    CREATED+=("$out.$EXT")
    tarvol "$1" | enc "$out"
  else
    echo "backup volume $1"
    CREATED+=("$out")
    tarvol "$1" >"$out"
  fi
}
volume web-auth 1
volume shipper-state 0
volume collector-state 1

# Набор полон: признак ставится последним, после него сбой набор уже не откатывает.
CREATED+=("$BACKUP_DIR/$NAME.complete")
: >"$BACKUP_DIR/$NAME.complete"
DONE=1

# ── Ротация ──────────────────────────────────────────────────────────────────
# Текущий набор полон и в ротацию не входит, поэтому последний полный не удаляется.
# Возраст — по первому существующему файлу набора; ошибка ротации набор не трогает.
rotate() {
  local s x f
  scan_sets
  for s in ${ALL_SETS[@]+"${ALL_SETS[@]}"}; do
    for x in $SET_SUFFIXES; do
      f="$BACKUP_DIR/$s$x"
      [ -e "$f" ] && break
    done
    if [ -n "$(find "$f" -maxdepth 0 -mtime +"$KEEP" -print)" ]; then
      echo "ротация: удаляю $s"
      delete_set "$s"
    fi
  done
}
echo "ротация: старше $KEEP дней"
rotate || say_err "ротация не удалась — набор $NAME сохранён"
for f in "$BACKUP_DIR/$NAME"*; do ls -la "$f" || true; done
echo "готово: $NAME"
