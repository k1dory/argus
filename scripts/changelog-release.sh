#!/usr/bin/env bash
# Собирает раздел версии в CHANGELOG.md из фрагментов changes/unreleased/ (все файлы,
# включая скрытые и вложенные, кроме changes/unreleased/README.md) и записей,
# накопленных в «## Не выпущено», затем удаляет фрагменты. «Не выпущено» остаётся
# пустым заголовком.
#   scripts/changelog-release.sh 1.0.0-rc29 [2026-11-01]
# Порядок: старые записи «Не выпущено», затем фрагменты по пути (LC_ALL=C).
#
# Отказ без изменений: раздел версии уже есть; выпускать нечего; changes или
# changes/unreleased — симлинк или ведёт за пределы checkout; среди фрагментов симлинк,
# каталог с именем *.md или не обычный файл (иначе в публикуемый CHANGELOG мог бы
# попасть чужой файл, например .env); обход каталога неполон (find с ошибкой).
#
# Порядок изменений — так, чтобы сбой ничего не терял: новый CHANGELOG собирается во
# временный файл рядом с ним; фрагменты снимаются только из индекса (git rm --cached:
# при index.lock — отказ, ничего не изменено); CHANGELOG заменяется атомарным mv (при
# ошибке индекс восстанавливается); и лишь затем файлы фрагментов удаляются из дерева.
# VERSION скрипт не меняет — это отдельный шаг релиза.
set -euo pipefail
export LC_ALL=C

ver="${1:?версия, например 1.0.0-rc29}"
date="${2:-$(date -u +%F)}"
root="$(cd -P "$(dirname "$0")/.." && pwd)"
log="$root/CHANGELOG.md"
dir="$root/changes/unreleased"
readme="$dir/README.md"
fail() { echo "$*" >&2; exit 1; }

# Строки передаются в awk через ENVIRON: -v раскрывает «\t» и прочие escape-последовательности.
export CL_VER="$ver" CL_DATE="$date"
if awk 'index($0, "## " ENVIRON["CL_VER"] " — ") == 1 { found = 1 } END { exit !found }' "$log"; then
    fail "в CHANGELOG.md уже есть раздел $ver"
fi
awk '$0 == "## Не выпущено" { found = 1 } END { exit !found }' "$log" ||
    fail "в CHANGELOG.md нет раздела «## Не выпущено»"

for d in "$root/changes" "$dir"; do
    [ ! -L "$d" ] || fail "${d#"$root"/} — симлинк; фрагменты берутся только из самого checkout"
done
if [ -e "$dir" ]; then
    [ -d "$dir" ] || fail "changes/unreleased — не каталог"
    [ "$(cd -P "$dir" && pwd)" = "$dir" ] || fail "changes/unreleased ведёт за пределы checkout"
fi

work="$(mktemp -d)"
new="$(mktemp "$root/.CHANGELOG.md.XXXXXX")"
trap 'rm -rf -- "$work"; rm -f -- "$new"' EXIT

frags=()
if [ -d "$dir" ]; then
    # find не следует за симлинками; его ошибку (нечитаемый подкаталог) проверяем явно —
    # неполный обход выпустил бы часть фрагментов и потерял остальные.
    find "$dir" -mindepth 1 \( -type d -name '*.md' -o ! -type d \) -print0 > "$work/list" ||
        fail "не удалось обойти changes/unreleased — релиз не собран"
    sort -z "$work/list" > "$work/sorted"
    while IFS= read -r -d '' f; do
        [ "$f" = "$readme" ] && continue
        if [ -L "$f" ] || [ ! -f "$f" ]; then
            fail "фрагмент не обычный файл (симлинк, каталог или устройство): ${f#"$root"/}"
        fi
        frags+=("$f")
    done < "$work/sorted"
fi

{
    # Записи «Не выпущено» — от заголовка до следующего «## ».
    awk '$0 == "## Не выпущено" { p = 1; next } /^## / { p = 0 } p' "$log"
    for f in "${frags[@]}"; do
        printf '\n'
        cat -- "$f"
        [ -z "$(tail -c 1 -- "$f")" ] || printf '\n'
    done
} | awk 'NF { started = 1 } started { lines[++n] = $0 } END { while (n > 0 && lines[n] == "") n--; for (i = 1; i <= n; i++) print lines[i] }' > "$work/body"

[ -s "$work/body" ] || fail "нечего выпускать: «Не выпущено» и changes/unreleased пусты"

CL_BODY="$work/body" awk '
    $0 == "## Не выпущено" {
        print; print ""
        print "## " ENVIRON["CL_VER"] " — " ENVIRON["CL_DATE"]; print ""
        while ((getline line < ENVIRON["CL_BODY"]) > 0) print line
        print ""
        skip = 1; next
    }
    skip && /^## / { skip = 0 }
    !skip { print }
' "$log" > "$new"
chmod "$(stat -c %a "$log" 2>/dev/null || stat -f %Lp "$log")" "$new" 2>/dev/null || true

# Пути Git — буквально (--literal-pathspecs), не как шаблоны.
tracked=()
for f in "${frags[@]}"; do
    if git -C "$root" --literal-pathspecs ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
        tracked+=("$f")
    fi
done
if [ ${#tracked[@]} -gt 0 ]; then
    git -C "$root" --literal-pathspecs rm -q --cached -- "${tracked[@]}" ||
        fail "git rm не выполнен (занят индекс?) — ничего не изменено, повторите"
fi
if ! mv -f -- "$new" "$log"; then
    [ ${#tracked[@]} -eq 0 ] || git -C "$root" --literal-pathspecs reset -q -- "${tracked[@]}" || true
    fail "не удалось записать CHANGELOG.md — фрагменты и индекс оставлены как были"
fi
[ ${#frags[@]} -eq 0 ] || rm -f -- "${frags[@]}"
echo "CHANGELOG.md: раздел $ver — $date, фрагментов: ${#frags[@]}"
