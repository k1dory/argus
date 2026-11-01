#!/usr/bin/env bash
# Обновить таблицу IP→ASN коллектора: scripts/asn-update.sh <каталог> [URL].
# По умолчанию — ip2asn-combined.tsv.gz с iptoasn.com (PDDL, без ключа). Файл
# скачивается во временный в том же каталоге, проверяется (gzip целиком, пять
# полей в каждой строке, не меньше ASN_DB_MIN_ROWS строк) и только потом
# атомарно заменяет ip2asn-combined.tsv.gz. Сбой — прежний файл остаётся, код
# выхода ненулевой. Коллектор перечитывает файл по mtime и проверяет его ещё раз
# (порядок диапазонов, адреса): битую таблицу он не примет и сам.
set -euo pipefail

dir=${1:?usage: asn-update.sh <каталог> [URL]}
url=${2:-${ASN_DB_URL:-https://iptoasn.com/data/ip2asn-combined.tsv.gz}}
min=${ASN_DB_MIN_ROWS:-10000}
dest="$dir/ip2asn-combined.tsv.gz"

[[ -d $dir ]] || { echo "asn-update: нет каталога $dir" >&2; exit 2; }
[[ $min =~ ^[1-9][0-9]*$ ]] || { echo "asn-update: ASN_DB_MIN_ROWS — положительное число" >&2; exit 2; }

tmp=$(mktemp "$dir/.ip2asn.XXXXXX")
trap 'rm -f "$tmp"' EXIT

curl -fsSL --proto '=https,file' --max-time 600 --retry 3 -o "$tmp" "$url"
if ! gzip -t "$tmp" 2>/dev/null; then
  echo "asn-update: не gzip или файл обрезан: $url" >&2
  exit 1
fi
read -r rows bad < <(gzip -dc "$tmp" | awk -F'\t' 'NF { n++; if (NF != 5) b++ } END { print n + 0, b + 0 }')
if (( bad > 0 )); then
  echo "asn-update: $bad строк не из пяти полей — файл не похож на iptoasn TSV" >&2
  exit 1
fi
if (( rows < min )); then
  echo "asn-update: $rows строк, нужно не меньше $min" >&2
  exit 1
fi
chmod 0644 "$tmp"
mv -f "$tmp" "$dest"
trap - EXIT
echo "asn-update: $dest — $rows диапазонов"
