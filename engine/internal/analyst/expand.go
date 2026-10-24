package analyst

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// templateVars — плейсхолдеры шаблонов исполнителей (respond.http body/url/
// headers), которые подставляет движок в момент блокировки, а не конфиг.
// ExpandEnv их не трогает никогда: подстановка пустоты давала бы NGFW
// запрос {"ip": ""}.
var templateVars = map[string]bool{"ip": true, "incident": true, "reason": true}

// ExpandEnv — ${VAR} и ${VAR:-default}; os.ExpandEnv второе не умеет.
// Подставляются только переменные, которые есть в окружении; ${VAR:-default}
// даёт default, если VAR не задана или пуста (как в shell и docker compose).
// Плейсхолдер без переменной в окружении и без default остаётся в тексте как
// есть — это либо шаблон исполнителя (${ip}), либо ошибка окружения, которую
// LoadConfig покажет в логе, а не спрячет за пустой строкой.
// Значение подставляется так, чтобы не сломать YAML: внутри кавычек —
// экранируется под тип кавычек, в открытом контексте значение с
// YAML-значимыми символами (": ", "#", "[", "{", перевод строки…) берётся в
// двойные кавычки. Простые значения (587, false, host.corp) остаются как есть
// и сохраняют тип. Пароль с «#» или «: » иначе молча ломал бы конфиг.
func ExpandEnv(s string) string {
	out, _ := expandEnv(s)
	return out
}

// expandEnv — ExpandEnv плюс список плейсхолдеров, оставленных без подстановки
// (без шаблонных ${ip}/${incident}/${reason}), отсортированный и без дублей.
func expandEnv(s string) (string, []string) {
	var b strings.Builder
	last := 0
	unresolved := map[string]bool{}
	for _, m := range envRe.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(s[last:m[0]])
		last = m[1]
		name := s[m[2]:m[3]]
		if templateVars[name] {
			b.WriteString(s[m[0]:m[1]])
			continue
		}
		v, ok := os.LookupEnv(name)
		if m[4] >= 0 && v == "" {
			v, ok = s[m[4]:m[5]], true
		}
		if !ok {
			unresolved[name] = true
			b.WriteString(s[m[0]:m[1]])
			continue
		}
		b.WriteString(yamlSafe(v, s[lineStart(s, m[0]):m[0]]))
	}
	b.WriteString(s[last:])
	names := make([]string, 0, len(unresolved))
	for n := range unresolved {
		names = append(names, n)
	}
	sort.Strings(names)
	return b.String(), names
}

func lineStart(s string, i int) int {
	if j := strings.LastIndexByte(s[:i], '\n'); j >= 0 {
		return j + 1
	}
	return 0
}

// quoteContext — в какой кавычке стоит плейсхолдер: проход по строке до него
// с учётом того, что удвоенный апостроф внутри '…' и \" внутри "…" —
// экранирование, а не закрытие. 0 — открытый (plain) контекст. Считать кавычки по всей строке
// нельзя: в body: '{"ip": "${ip}", "c": "${X}"}' плейсхолдер стоит внутри
// одинарных, хотя двойных перед ним нечётное число.
func quoteContext(before string) byte {
	var q byte
	for i := 0; i < len(before); i++ {
		c := before[i]
		switch q {
		case 0:
			if c == '"' || c == '\'' {
				q = c
			}
		case '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				q = 0
			}
		case '\'':
			if c == '\'' {
				q = 0 // '' переоткроет на следующей итерации — это экранированный апостроф
			}
		}
	}
	return q
}

// yamlSafe — значение под контекст: before — текст строки до плейсхолдера.
func yamlSafe(v, before string) string {
	switch quoteContext(before) {
	case '"':
		q := strconv.Quote(v)
		return q[1 : len(q)-1]
	case '\'':
		return strings.ReplaceAll(v, "'", "''")
	}
	if v == "" || !strings.ContainsAny(v, ":#[]{},&*!|>'\"%@`\n\t\\") || plainOK(v) {
		return v
	}
	return strconv.Quote(v)
}

// plainOK — символы из списка встречаются, но в позициях, где YAML их не
// трактует: "host:8080", "a/b:c" без пробела после двоеточия допустимы.
func plainOK(v string) bool {
	if strings.ContainsAny(v, "#[]{},&*!|>'\"%@`\n\t\\") {
		return false
	}
	return !strings.Contains(v, ": ") && !strings.HasSuffix(v, ":")
}
