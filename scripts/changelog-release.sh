#!/usr/bin/env bash
# Собирает раздел версии в CHANGELOG.md из фрагментов changes/unreleased/ (все файлы,
# включая скрытые и вложенные, кроме changes/unreleased/README.md) и записей,
# накопленных в «## Не выпущено», затем удаляет фрагменты (git rm). «Не выпущено»
# остаётся пустым заголовком. VERSION скрипт не меняет — это отдельный шаг релиза.
#   scripts/changelog-release.sh 1.0.0-rc29 [2026-11-01]
#
# Только с чистого дерева: changes/, CHANGELOG.md и VERSION без незакоммиченных и
# staged-изменений, в changes/ нет неотслеживаемых (и игнорируемых) файлов. Поэтому
# всё, что скрипт читает и трогает, лежит в HEAD: фрагменты берутся из индекса
# (git ls-files / git cat-file), а не с диска, и откат после любой ошибки —
#   git checkout HEAD -- CHANGELOG.md changes && git reset -q -- CHANGELOG.md changes
# Отказ: дерево не чисто; раздел версии уже есть; выпускать нечего; фрагмент или сам
# changes / changes/unreleased — симлинк в Git (mode 120000) или не обычный файл.
set -euo pipefail
export LC_ALL=C

ver="${1:?версия, например 1.0.0-rc29}"
date="${2:-$(date -u +%F)}"
root="$(cd -P "$(dirname "$0")/.." && pwd)"
cd "$root"
log=CHANGELOG.md
fail() { echo "$*" >&2; exit 1; }
rollback="git checkout HEAD -- CHANGELOG.md changes && git reset -q -- CHANGELOG.md changes"

# --- чистое дерево -----------------------------------------------------------------
git rev-parse --verify -q HEAD >/dev/null || fail "нет коммита HEAD"
git diff --quiet -- CHANGELOG.md VERSION changes ||
    fail "незакоммиченные изменения в CHANGELOG.md, VERSION или changes/ — закоммитьте их"
git diff --cached --quiet -- CHANGELOG.md VERSION changes ||
    fail "staged-изменения в CHANGELOG.md, VERSION или changes/ — закоммитьте их"
[ -z "$(git ls-files -o -- changes)" ] ||
    fail "в changes/ есть неотслеживаемые файлы — закоммитьте фрагменты или удалите лишнее"

# --- проверки содержимого ------------------------------------------------------------
# Строки передаются в awk через ENVIRON: -v раскрывает «\t» и прочие escape-последовательности.
export CL_VER="$ver" CL_DATE="$date"
awk 'index($0, "## " ENVIRON["CL_VER"] " — ") == 1 { found = 1 } END { exit !found }' "$log" &&
    fail "в CHANGELOG.md уже есть раздел $ver"
awk '$0 == "## Не выпущено" { found = 1 } END { exit !found }' "$log" ||
    fail "в CHANGELOG.md нет раздела «## Не выпущено»"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

# Фрагменты — из индекса (он совпадает с HEAD и деревом). Симлинк в самом пути
# (changes или changes/unreleased) git показывает записью mode 120000 этого пути.
git ls-files -s -z -- changes > "$work/stage"
frags=()
while IFS= read -r -d '' entry; do
    mode="${entry%% *}"; path="${entry#*$'\t'}"
    [ "$path" = changes/unreleased/README.md ] && continue
    case "$path" in
        changes/unreleased/*) ;;
        changes|changes/unreleased) fail "$path в Git — не каталог (mode $mode); фрагменты берутся только из каталога" ;;
        *) continue ;;
    esac
    [ "$mode" = 100644 ] || [ "$mode" = 100755 ] ||
        fail "в changes/ запись Git не обычный файл (mode $mode): $path"
    frags+=("$path")
done < "$work/stage"   # индекс Git упорядочен по пути побайтно (как LC_ALL=C)

{
    awk '$0 == "## Не выпущено" { p = 1; next } /^## / { p = 0 } p' "$log"
    for f in "${frags[@]}"; do
        printf '\n'
        git cat-file blob ":$f" > "$work/frag"
        cat -- "$work/frag"
        [ -z "$(tail -c 1 -- "$work/frag")" ] || printf '\n'
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
' "$log" > "$work/new"

# --- изменения: git rm фрагментов, затем CHANGELOG.md --------------------------------
# Сбой (index.lock, нет прав) — сообщение с командой отката; повтор после неё —
# обычная первая сборка.
trap 'rc=$?; rm -rf -- "$work"; [ $rc -eq 0 ] || echo "релиз не завершён; откатить: $rollback" >&2' EXIT
if [ ${#frags[@]} -gt 0 ]; then
    git --literal-pathspecs rm -q -- "${frags[@]}"
fi
cat -- "$work/new" > "$log"
echo "CHANGELOG.md: раздел $ver — $date, фрагментов: ${#frags[@]}"
