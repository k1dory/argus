#!/usr/bin/env bash
# Собирает раздел версии в CHANGELOG.md из фрагментов changes/unreleased/ (все файлы,
# включая скрытые и вложенные, кроме changes/unreleased/README.md) и записей,
# накопленных в «## Не выпущено», затем удаляет фрагменты. «Не выпущено» остаётся
# пустым заголовком.
#   scripts/changelog-release.sh 1.0.0-rc29 [2026-11-01]
# Порядок: старые записи «Не выпущено», затем фрагменты по пути (LC_ALL=C).
# Отказ без изменений: раздел версии уже есть, выпускать нечего, среди фрагментов
# симлинк (он мог бы перенести в публикуемый CHANGELOG чужой файл, например .env),
# каталог с именем *.md или не обычный файл. Сначала удаляются фрагменты, потом
# пишется CHANGELOG.md: упавший git rm (index.lock) оставляет всё как было, и
# повторный запуск проходит. VERSION скрипт не меняет — это отдельный шаг релиза.
set -euo pipefail
export LC_ALL=C

ver="${1:?версия, например 1.0.0-rc29}"
date="${2:-$(date -u +%F)}"
root="$(cd "$(dirname "$0")/.." && pwd)"
log="$root/CHANGELOG.md"
dir="$root/changes/unreleased"
readme="$dir/README.md"

# Точное сравнение строки заголовка: версия — не регулярное выражение.
if awk -v h="## $ver — " 'index($0, h) == 1 { found = 1 } END { exit !found }' "$log"; then
    echo "в CHANGELOG.md уже есть раздел $ver" >&2; exit 1
fi
awk '$0 == "## Не выпущено" { found = 1 } END { exit !found }' "$log" ||
    { echo "в CHANGELOG.md нет раздела «## Не выпущено»" >&2; exit 1; }

frags=()
if [ -d "$dir" ]; then
    while IFS= read -r -d '' f; do
        [ "$f" = "$readme" ] && continue
        if [ -L "$f" ] || [ ! -f "$f" ]; then
            echo "фрагмент не обычный файл (симлинк, каталог или устройство): ${f#"$root"/}" >&2; exit 1
        fi
        frags+=("$f")
    done < <(find "$dir" -mindepth 1 \( -type d -name '*.md' -o ! -type d \) -print0 | sort -z)
fi

body="$(mktemp)"; new="$(mktemp)"
trap 'rm -f "$body" "$new"' EXIT
{
    # Записи «Не выпущено» — от заголовка до следующего «## ».
    awk '$0 == "## Не выпущено" { p = 1; next } /^## / { p = 0 } p' "$log"
    for f in "${frags[@]}"; do
        printf '\n'
        cat -- "$f"
        [ -z "$(tail -c 1 -- "$f")" ] || printf '\n'
    done
} | awk 'NF { started = 1 } started { lines[++n] = $0 } END { while (n > 0 && lines[n] == "") n--; for (i = 1; i <= n; i++) print lines[i] }' > "$body"

[ -s "$body" ] || { echo "нечего выпускать: «Не выпущено» и changes/unreleased пусты" >&2; exit 1; }

awk -v ver="$ver" -v date="$date" -v body="$body" '
    $0 == "## Не выпущено" {
        print; print ""
        print "## " ver " — " date; print ""
        while ((getline line < body) > 0) print line
        print ""
        skip = 1; next
    }
    skip && /^## / { skip = 0 }
    !skip { print }
' "$log" > "$new"

# Фрагменты — до записи CHANGELOG.md; пути Git — буквально, не как pathspec-шаблоны.
tracked=(); untracked=()
for f in "${frags[@]}"; do
    if git -C "$root" --literal-pathspecs ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
        tracked+=("$f")
    else
        untracked+=("$f")
    fi
done
[ ${#tracked[@]} -eq 0 ] || git -C "$root" --literal-pathspecs rm -q -f -- "${tracked[@]}"
[ ${#untracked[@]} -eq 0 ] || rm -f -- "${untracked[@]}"

cat "$new" > "$log"
echo "CHANGELOG.md: раздел $ver — $date, фрагментов: ${#frags[@]}"
