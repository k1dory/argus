#!/usr/bin/env bash
# Обновить таблицу IP→ASN коллектора: scripts/asn-update.sh <каталог> [URL].
# По умолчанию — ip2asn-combined.tsv.gz с iptoasn.com (PDDL, без ключа). Файл
# скачивается во временный в том же каталоге и проверяется тем же разбором, что
# у коллектора (`collector asn-check`: поля, адреса, ASN, порядок диапазонов без
# пересечений, не меньше ASN_DB_MIN_ROWS строк). Только годная таблица атомарно
# заменяет ip2asn-combined.tsv.gz. Сбой — прежний файл остаётся, код ненулевой.
#
# Проверяющий: $ASN_CHECK (команда, получает путь файла), иначе `collector` из
# PATH, иначе образ запущенного контейнера collector этого стека (docker run без
# сети, только чтение). Нет ни одного — таблица не заменяется.
set -euo pipefail

dir=${1:?usage: asn-update.sh <каталог> [URL]}
url=${2:-${ASN_DB_URL:-https://iptoasn.com/data/ip2asn-combined.tsv.gz}}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

[[ -d $dir && ! -L $dir ]] || { echo "asn-update: $dir — не каталог" >&2; exit 2; }
# Абсолютный путь: docker run -v принял бы «data/…» за имя тома, а не за путь.
dir=$(cd "$dir" && pwd)
dest="$dir/ip2asn-combined.tsv.gz"

# Порог — тот же, что у коллектора: ASN_DB_MIN_ROWS из .env стека (compose передаёт
# его в контейнер), иначе из окружения, иначе 10000. Cron .env не экспортирует, а
# таблица ниже порога коллектора после рестарта была бы отвергнута. .env не
# исполняется (там секреты): читается только эта строка, последняя побеждает.
env_min=
if [[ -f $root/.env ]]; then
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line =~ ^[[:space:]]*ASN_DB_MIN_ROWS[[:space:]]*=[[:space:]]*[\"\']?([^\"\'[:space:]#]*) ]]; then
      env_min=${BASH_REMATCH[1]}
    fi
  done < "$root/.env"
fi
min=${env_min:-${ASN_DB_MIN_ROWS:-10000}}
[[ $min =~ ^[1-9][0-9]*$ ]] || { echo "asn-update: ASN_DB_MIN_ROWS — положительное число" >&2; exit 2; }
# mv в симлинк на каталог положил бы файл внутрь чужого каталога, а в симлинк на
# файл — заменил бы ссылку; на месте таблицы допустим только обычный файл.
if [[ -L $dest || ( -e $dest && ! -f $dest ) ]]; then
  echo "asn-update: $dest — не обычный файл, замена отклонена" >&2
  exit 2
fi

check() {
  if [[ -n ${ASN_CHECK:-} ]]; then
    # shellcheck disable=SC2086 # команда с аргументами задаётся строкой
    ASN_DB_MIN_ROWS=$min $ASN_CHECK "$1"
  elif command -v collector >/dev/null 2>&1; then
    ASN_DB_MIN_ROWS=$min collector asn-check "$1"
  elif command -v docker >/dev/null 2>&1 && cid=$(docker compose --project-directory "$root" ps -q collector 2>/dev/null) && [[ -n $cid ]]; then
    img=$(docker inspect -f '{{.Image}}' "$cid")
    docker run --rm --network none --read-only -e ASN_DB_MIN_ROWS="$min" \
      -v "$1:/check.tsv.gz:ro" "$img" asn-check /check.tsv.gz
  else
    echo "asn-update: нет проверяющего (ASN_CHECK, collector в PATH или запущенный контейнер collector)" >&2
    return 2
  fi
}

tmp=$(mktemp "$dir/.ip2asn.XXXXXX")
trap 'rm -f "$tmp"' EXIT

curl -fsSL --proto '=https,file' --max-time 600 --retry 3 -o "$tmp" "$url"
if ! gzip -t "$tmp" 2>/dev/null; then
  echo "asn-update: не gzip или файл обрезан: $url" >&2
  exit 1
fi
# Контейнер проверяющего работает не от root: файл должен быть читаем.
chmod 0644 "$tmp"
if ! rows=$(check "$tmp"); then
  echo "asn-update: таблица не прошла проверку, прежний файл оставлен" >&2
  exit 1
fi
mv -f "$tmp" "$dest"
trap - EXIT
echo "asn-update: $dest — $rows диапазонов"
