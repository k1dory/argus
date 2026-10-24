package redact

// Не ловится (известные пробелы редакции; оставлены сознательно, чтобы не
// резать обычный текст журналов):
//
//   - Hex-строка без имени ключа (40 символов и любой другой длины): по виду
//     не отличить от SHA-1, коммита git, отпечатка или идентификатора, которые
//     нужны для разбора. Секрет в hex ловится только по имени ключа
//     (token=, secret:, ?sig=…) или по префиксу известного формата.
//   - Секрет после пробела, а не «:» или «=», если он короче 16 символов или
//     без цифр («password hunter»): иначе пропадали бы фразы журналов
//     («token rotated», «password changed»). У русских имён ключей
//     («с паролем Hunter2Hunter2») хватает букв и цифр от 8 символов.
//   - Словоформы имён («Сидоровой» при записи «Сидорова Анна») — только
//     отдельными записями словаря Options.Names.
//   - E-mail через « at » без точки, «_» или цифр в локальной части и без
//     домена словами «dot» («ivan at example.org»): иначе задевался бы
//     обычный текст («uploaded at storage.internal»).
//
// Перередакция (ложные срабатывания оставлены сознательно: лучше лишнее
// скрыть, чем пропустить):
//
//   - «build_42 at runner.internal» — логин с цифрой и домен: становится
//     псевдонимом e-mail.
//   - Десять цифр с 9 в начале («port 916 123 45 67», «size 9161234567
//     bytes») — становятся телефоном.
//   - «?code=200» и любой code= в URL — значение скрывается (OAuth code).
//
// Ловится шаблоном (там же, в bypass_test.go): «собака», « at … dot »,
// телефоны 916 123-45-67, (916) 123-45-67 и 8.916.123.45.67, обратные кавычки
// в ErrorText, словоформы русских имён ключей («паролем», «токены», «ключ
// API»), &amp; перед параметром URL.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// Shape — разрешённый набор полей JSON-объекта. Ключ с nil — лист: строки
// проходят Text, вложенные объекты — Generic. Ключ с непустой формой —
// объект или массив объектов этой формы. Ключ Any разрешает любые ключи с
// формой Shape[Any]. Остальные ключи удаляются.
type Shape map[string]Shape

// Any — «любой ключ» в Shape.
const Any = "*"

// Leaf — разрешённое поле-лист (для читаемости форм).
var Leaf Shape

// Policy — как редактировать документ.
type Policy struct {
	// Shape — разрешённые поля верхнего уровня; nil — все (Generic).
	Shape Shape
	// Drop — ключи, удаляемые на любой глубине (raw, full_log).
	Drop map[string]bool
	// Subjects — ключи, чьи строковые значения — субъекты (actor_name,
	// owner, author…): значение целиком → псевдоним, а его вхождения в
	// остальной текст документа — тоже.
	Subjects map[string]bool
	// Hosts — ключи-узлы (node, agent_name): машина человека → псевдоним
	// host-…, серверные имена — как есть (Redactor.Host).
	Hosts map[string]bool
}

type doc struct {
	r        *Redactor
	p        Policy
	subjects []string
}

// Document редактирует разобранный JSON (map[string]any / []any / string …)
// и возвращает новое значение; исходное не меняется.
// known — дополнительные исходные значения субъектов для замены в тексте.
func (r *Redactor) Document(v any, p Policy, known ...string) any {
	d := &doc{r: r, p: p}
	if r.pseudo {
		seen := map[string]bool{}
		for _, k := range known {
			if k = strings.TrimSpace(k); utf8.RuneCountInString(k) >= 3 {
				seen[k] = true
			}
		}
		d.collect(v, seen)
		for s := range seen {
			d.subjects = append(d.subjects, s)
		}
		// Длинные — первыми: «svc-backup-2» не должен стать «subj-…-2».
		sort.Slice(d.subjects, func(i, j int) bool { return len(d.subjects[i]) > len(d.subjects[j]) })
	}
	if p.Shape == nil {
		return d.generic(v)
	}
	return d.shaped(v, p.Shape)
}

// JSON — Document для тела ответа. Числа сохраняют точность (UseNumber).
// Невалидный JSON — ошибка: сырое тело в модель не уходит.
func (r *Redactor) JSON(body []byte, p Policy) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("ответ не разбирается как JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("ответ не разбирается как JSON: данные после конца документа")
	}
	return json.Marshal(r.Document(v, p))
}

func (d *doc) collect(v any, seen map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if d.p.Drop[k] {
				continue
			}
			if s, ok := child.(string); ok && d.p.Subjects[k] && utf8.RuneCountInString(s) >= 3 {
				seen[s] = true
			}
			d.collect(child, seen)
		}
	case []any:
		for _, child := range t {
			d.collect(child, seen)
		}
	}
}

func (d *doc) str(key, s string) string {
	if d.p.Subjects[key] {
		return d.r.Subject(s)
	}
	if d.p.Hosts[key] {
		return d.r.Host(s, d.subjects...)
	}
	return d.r.text(s, d.subjects)
}

// generic — все ключи, кроме Drop; строки — Text или Subject по ключу.
func (d *doc) generic(v any) any { return d.genericKey("", v) }

// key — имя ключа произвольного объекта: в ключ тоже может попасть секрет
// или логин (обогащение, словари). Ключи форм не трогаются — они из списка.
func (d *doc) key(k string) string {
	if !d.r.pseudo {
		return d.r.Secrets(k)
	}
	return d.r.text(k, d.subjects)
}

func (d *doc) genericKey(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if d.p.Drop[k] {
				continue
			}
			out[d.key(k)] = d.genericKey(k, child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = d.genericKey(key, child)
		}
		return out
	case string:
		return d.str(key, t)
	}
	return v
}

func (d *doc) shaped(v any, s Shape) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			if d.p.Drop[k] {
				continue
			}
			outKey := k
			sub, ok := s[k]
			if !ok {
				if sub, ok = s[Any]; !ok {
					continue
				}
				outKey = d.key(k)
			}
			if sub == nil {
				out[outKey] = d.genericKey(k, child)
			} else {
				out[outKey] = d.shaped(child, sub)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = d.shaped(child, s)
		}
		return out
	case string:
		return d.r.text(t, d.subjects)
	}
	return v
}
