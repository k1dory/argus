#!/usr/bin/env bash
# Собирает раздел версии в CHANGELOG.md из фрагментов changes/unreleased/*.md
# (кроме README.md) и записей, накопленных в «## Не выпущено», затем удаляет
# фрагменты. «Не выпущено» остаётся пустым заголовком.
#   scripts/changelog-release.sh 1.0.0-rc29 [2026-11-01]
# Порядок пунктов: сначала старые записи «Не выпущено», затем фрагменты по имени
# файла. VERSION скрипт не меняет — это отдельный шаг релиза.
set -euo pipefail

ver="${1:?версия, например 1.0.0-rc29}"
date="${2:-$(date -u +%F)}"
root="$(cd "$(dirname "$0")/.." && pwd)"
log="$root/CHANGELOG.md"
dir="$root/changes/unreleased"

grep -q "^## $ver " "$log" && { echo "в CHANGELOG.md уже есть раздел $ver" >&2; exit 1; }
grep -q '^## Не выпущено$' "$log" || { echo "в CHANGELOG.md нет раздела «## Не выпущено»" >&2; exit 1; }

shopt -s nullglob
frags=()
for f in "$dir"/*.md; do
    [ "$(basename "$f")" = README.md ] || frags+=("$f")
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
{
    # Записи «Не выпущено» — от заголовка до следующего «## », без пустых краёв.
    awk '/^## Не выпущено$/{p=1; next} /^## /{p=0} p' "$log"
    for f in "${frags[@]}"; do
        printf '\n'
        cat "$f"
    done
} | awk 'NF{started=1} started' | awk '{lines[NR]=$0} END{n=NR; while (n>0 && lines[n]=="") n--; for (i=1;i<=n;i++) print lines[i]}' > "$tmp"

[ -s "$tmp" ] || { echo "нечего выпускать: «Не выпущено» и changes/unreleased пусты" >&2; exit 1; }

awk -v ver="$ver" -v date="$date" -v body="$tmp" '
    /^## Не выпущено$/ {
        print; print ""
        print "## " ver " — " date; print ""
        while ((getline line < body) > 0) print line
        print ""
        skip=1; next
    }
    skip && /^## / { skip=0 }
    !skip { print }
' "$log" > "$log.new"
mv "$log.new" "$log"

for f in "${frags[@]}"; do
    if git -C "$root" ls-files --error-unmatch "$f" >/dev/null 2>&1; then git -C "$root" rm -q -f "$f"; else rm -f "$f"; fi
done
echo "CHANGELOG.md: раздел $ver — $date, фрагментов: ${#frags[@]}"
