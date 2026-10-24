// Package redact — редакция данных ARGUS до выдачи облачной модели: секреты,
// канарейки, ПДн (e-mail, телефоны, домашние каталоги, субъекты) и опасные
// для рендера ссылки. Один и тот же код у argus-mcp и у шлюза публикации,
// поэтому псевдонимы совпадают везде, где задан один ключ ARGUS_PSEUDONYM_KEY.
//
// Редакция по шаблонам не гарантирует отсутствия ПДн: имена людей в
// свободном тексте шаблонами не ловятся (для них — словарь Options.Names),
// а флаг pii события — только дополнительный сигнал.
package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Options — что делать помимо удаления секретов (оно включено всегда).
type Options struct {
	// Key — HMAC-ключ псевдонимов и отпечатков секретов. Пусто — случайный
	// на процесс: псевдонимы стабильны в процессе, но не совпадут с другими.
	Key []byte
	// Pseudonymize — субъекты, локальная часть e-mail, телефоны и имена в
	// домашних каталогах заменяются псевдонимами.
	Pseudonymize bool
	// Defang — ссылки обезвреживаются (hxxp://, mention[:]//): пересказ
	// payload не превращается в картинку, автоссылку или упоминание.
	Defang bool
	// Canaries — дополнительные литералы-канарейки (регистр не важен).
	Canaries []string
	// Names — словарь имён людей (ФИО, логины из каталога): в тексте
	// заменяются псевдонимами. Без словаря имена в свободном тексте остаются.
	Names []string
	// MaxReverse — сколько псевдонимов субъектов помнить для Resolve
	// (0 — 100 000). Старые вытесняются.
	MaxReverse int
}

// Redactor безопасен для одновременного использования.
type Redactor struct {
	key       []byte
	pseudo    bool
	defang    bool
	canaries  []string // в нижнем регистре
	names     []string // по убыванию длины
	nameWords []string // слова записей names длиннее 3 букв, по убыванию длины
	maxRev    int
	mu        sync.Mutex
	reverse   map[string]string
	revOrder  []string
	revCursor int
}

func New(o Options) *Redactor {
	key := o.Key
	if len(key) == 0 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	r := &Redactor{key: key, pseudo: o.Pseudonymize, defang: o.Defang, maxRev: o.MaxReverse, reverse: map[string]string{}}
	if r.maxRev <= 0 {
		r.maxRev = 100_000
	}
	for _, c := range o.Canaries {
		if c = strings.TrimSpace(c); c != "" {
			r.canaries = append(r.canaries, strings.ToLower(c))
		}
	}
	for _, n := range o.Names {
		if n = strings.TrimSpace(n); utf8.RuneCountInString(n) >= 3 {
			r.names = append(r.names, n)
		}
	}
	sort.Slice(r.names, func(i, j int) bool { return len(r.names[i]) > len(r.names[j]) })
	// «Сидорова Анна» ловит и «Анна Сидорова», и «Сидорова» отдельно:
	// каждое слово записи — само по себе имя. Словоформы (Сидоровой) —
	// только записями словаря.
	seen := map[string]bool{}
	for _, n := range r.names {
		seen[strings.ToLower(n)] = true
	}
	for _, n := range r.names {
		for _, w := range strings.Fields(n) {
			if lw := strings.ToLower(w); utf8.RuneCountInString(w) > 3 && !seen[lw] {
				seen[lw] = true
				r.nameWords = append(r.nameWords, w)
			}
		}
	}
	sort.Slice(r.nameWords, func(i, j int) bool { return len(r.nameWords[i]) > len(r.nameWords[j]) })
	return r
}

// PseudonymOf — псевдоним из значения фильтра: «subj-…» или «subj-…@домен»
// (так в тексте выглядит e-mail субъекта); ok=false — не псевдоним.
func PseudonymOf(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '@'); i > 0 {
		s = s[:i]
	}
	return s, IsPseudonym(s)
}

// Pseudonymizes — включены ли псевдонимы (профиль triage).
func (r *Redactor) Pseudonymizes() bool { return r.pseudo }

// CanaryLiterals — литералы-канарейки (Options.Canaries) в нижнем регистре,
// копия. Для проверок, которые сравнивают текст в своей нормальной форме
// (скелет вердикта у шлюза разбора).
func (r *Redactor) CanaryLiterals() []string { return append([]string(nil), r.canaries...) }

func (r *Redactor) mac(kind, v string, n int) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:n]
}

// Fingerprint — отпечаток секрета: один и тот же секрет даёт один и тот же
// отпечаток (можно сопоставить утечку и ротацию), подобрать короткий секрет
// по отпечатку без ключа нельзя.
func (r *Redactor) Fingerprint(secret string) string { return r.mac("secret", secret, 8) }

func (r *Redactor) secretMark(v string) string { return "[REDACTED:" + r.Fingerprint(v) + "]" }

// pseudonymRe — вид псевдонима субъекта.
var pseudonymRe = regexp.MustCompile(`^subj-[0-9a-f]{10}$`)

// IsPseudonym — строка выглядит как псевдоним субъекта.
func IsPseudonym(s string) bool { return pseudonymRe.MatchString(s) }

// Subject — псевдоним целого значения-субъекта (логин, учётка, владелец).
// Без Pseudonymize — значение без секретов.
func (r *Redactor) Subject(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return s
	}
	if !r.pseudo {
		return r.Secrets(s)
	}
	// Значение, похожее на псевдоним, тоже хешируется: атакующий не выдаст
	// свои действия за чужой псевдоним, назвав учётку «subj-…».
	p := "subj-" + r.mac("subject", s, 10)
	r.remember(p, s)
	return p
}

func (r *Redactor) remember(p, real string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.reverse[p]; ok {
		return
	}
	if len(r.revOrder) < r.maxRev {
		r.revOrder = append(r.revOrder, p)
	} else {
		delete(r.reverse, r.revOrder[r.revCursor])
		r.revOrder[r.revCursor] = p
		r.revCursor = (r.revCursor + 1) % r.maxRev
	}
	r.reverse[p] = real
}

// Resolve — исходное значение псевдонима, выданного этим процессом (для
// точных фильтров: модель знает только псевдоним).
func (r *Redactor) Resolve(p string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.reverse[p]
	return v, ok
}

var (
	// Любой блок закрытого ключа: PEM, OpenSSH, PGP (… PRIVATE KEY BLOCK),
	// зашифрованный; без END — до конца строки.
	privateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----[\s\S]*?(?:-----END [A-Z0-9 ]*-----|$)`)
	urlCredsRe   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@'"]+:[^/\s@'"]+@`)
	// Токены известных форматов по префиксу: GitHub, GitLab, Slack, AWS,
	// OpenAI/Anthropic, Google; JWT — и с пустой подписью (alg:none:
	// «eyJ….eyJ….»). Префиксы внутренних систем добавляются через Options.Canaries
	// или собственный шаблон при сборке.
	knownTokenRe = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_-]{20,}|glrt-[A-Za-z0-9_-]{16,}|gl(?:dt|ptt|cbt|soat|ft|imt|oas|ffct)-[A-Za-z0-9_-]{16,}|xox[abeprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)`)
	bearerRe     = regexp.MustCompile(`(?i)\b(bearer)(\s+)([A-Za-z0-9._~+/=-]{4,})`)
	authSchemeRe = regexp.MustCompile(`(?i)\b(basic|token)(\s+)([A-Za-z0-9._~+/=-]{12,})`)
	// Имя ключа с признаком секрета. Короткие pass/pw — только целым
	// сегментом имени (DB_PASS, "pw"), иначе цепляли бы compass, upward.
	// Русские имена — словоформами целиком («пароль», «паролем», «токены»), не
	// подстрокой: «ключевой» и «секретарь» не ключи; «ключ API», «ключ
	// доступа» — одно имя. X-Auth — заголовок с учётными данными.
	secretName = `(?:[A-Za-z0-9_.-]*(?:passw(?:or)?d|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth[_-]?key|session[_-]?id|cookie)[A-Za-z0-9_.-]*|(?:[A-Za-z0-9]+[_.-])*(?:pass|pw|x-auth)(?:[_.-][A-Za-z0-9]+)*|(?:[A-Za-z0-9_.-]*[_.-])?(?:парол(?:ь|я|ю|ем|е|и|ей|ям|ями|ях)|токен(?:а|у|ом|е|ы|ов|ам|ами|ах)?|секрет(?:а|у|ом|е|ы|ов|ам|ами|ах)?|ключ(?:а|у|ом|е|и|ей|ам|ами|ах)?)(?:\s+(?:API|доступа))?(?:[_.-][\p{L}\p{N}]+)*)`
	// Граница перед именем ключа: \b в Go — только ASCII и перед кириллицей
	// не срабатывает, поэтому граница — отдельная группа (её текст
	// возвращается как есть).
	keyStart = `(^|[^\p{L}\p{N}_])`
	// Значение в кавычках — целиком до закрывающей кавычки (с «,», «;» и
	// пробелами внутри): "password":"correct horse, battery".
	keyQuotedRe = regexp.MustCompile(`(?i)` + keyStart + `(` + secretName + `)(["']?\s*[:=]\s*)("([^"\\]|\\.)*"|'([^'\\]|\\.)*')`)
	// Без кавычек — до пробела или разделителя (env, toString(Map), --password=).
	keyValueRe = regexp.MustCompile(`(?i)` + keyStart + `(` + secretName + `)(\s*[:=]\s*|\s+)([^\s"',;&<>\[\]{}][^\s"',;&<>{}]{3,})`)
	// Параметры подписи и ключа в URL (?key=, &sig=, X-Amz-Signature, OAuth
	// code): короткое имя без признака секрета, значение — целиком до «&».
	urlParamRe = regexp.MustCompile(`(?i)((?:[?&]|&amp;)(?:key|sig|signature|x-amz-signature|x-amz-credential|access|code|auth)=)([^&\s#"'<>]+)`)
	// mysql -pS3cr3t: значение вплотную к -p (не порт: в нём есть буква).
	dashPRe  = regexp.MustCompile(`(^|\s)-p([^\s'"]{4,})`)
	canaryRe = regexp.MustCompile(`(?i)[A-Za-z0-9_-]*canary[A-Za-z0-9_-]*`)
	// Безымянный секрет в base64 (≥40 символов, есть заглавные, строчные и
	// цифры): hex-хеши (только строчные) и идентификаторы не задевает.
	blobRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)

	// Ключи-субъекты внутри строк (toString(Map), JSON, key=value, журнал
	// Windows, ECS) без учёта регистра и с точками: 'TargetUserName':'x'.
	subjectKVRe = regexp.MustCompile(`(?i)(["']?\b(?:[A-Za-z0-9_]+\.)*(?:user\.(?:name|full_name|email)|user|username|user_?name|login|logon_?name|account|account_?name|target_?user(?:_?name)?|subject_?user(?:_?name)?|src_?user|dst_?user|subject|actor|owner|author|approver|requester|assignee|initiator|created_?by|uid|upn|user_?principal_?name|principal[A-Za-z0-9_]*|sam_?account_?name|email|mail|e_?mail)["']?\s*[:=]\s*)(["']?)([^"',;&\s{}\[\]]{2,})`)
	// Логин в тексте журналов: «Failed password for [invalid user] x»,
	// «Accepted publickey for x», «session opened for user x», «by user x».
	loginTextRe = regexp.MustCompile(`(?i)\b((?:failed|accepted) \w+ for (?:invalid |illegal )?(?:user )?|for (?:invalid |illegal )?user |by user |logged in as |login of )([^\s,;:'"()\[\]]{2,})`)
	tildeHomeRe = regexp.MustCompile(`(^|[\s'"(=:])~([A-Za-z_][A-Za-z0-9._-]{1,31})`)
	// E-mail, в том числе кириллица/IDN и обфускация: [at], (at), {at}, « @ »,
	// « собака », « at »; [dot], (dot), « dot », « точка ».
	emailRe   = regexp.MustCompile(`(?i)([\p{L}\p{N}._%+-]+)(@|\s*(?:\[at\]|\(at\)|\{at\})\s*|\s+@\s+|\s+собака\s+|\s+at\s+)((?:[\p{L}\p{N}-]+(?:\.|\s*(?:\[dot\]|\(dot\)|\{dot\})\s*|\s+(?:dot|точка)\s+))+[\p{L}]{2,}|[\p{L}\p{N}-]+\.xn--[a-z0-9-]+)`)
	dotWordRe = regexp.MustCompile(`(?i)\s*(?:\[dot\]|\(dot\)|\{dot\})\s*|\s+(?:dot|точка)\s+`)
	// Телефоны: с «+»; российские 11 цифр с 7/8 (8 (495) …, 8-800-…, 7 916 …,
	// 8.916.123.45.67); мобильные 10 цифр с 9 без префикса (9161234567,
	// 916 123-45-67). IP не задевает: октета 9xx нет, а в 7/8-шаблоне пять
	// групп цифр.
	phoneRe   = regexp.MustCompile(`\+\d[\d\s().-]{7,}\d|\b[78][\s.(-]*\d{3}[\s.)-]*\d{3}[\s.-]*\d{2}[\s.-]*\d{2}\b|(?:\(9\d{2}\)|\b9\d{2})[\s.-]*\d{3}[\s.-]*\d{2}[\s.-]*\d{2}\b`)
	homeDirRe = regexp.MustCompile(`(?i)(/home/|/users/|[a-z]:\\{1,2}users\\{1,2})([^/\\\s"':;,]+)`)

	// Обезвреживание. http(s) — и с обратными слешами (https:/\host, браузер
	// нормализует), прочие схемы — с «://».
	httpRe   = regexp.MustCompile(`(?i)\b(https?):[/\\]+`)
	schemeRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{1,15})://`)
	scriptRe = regexp.MustCompile(`(?i)\b(javascript|vbscript|data):`)
	// Ссылка без схемы: //host (protocol-relative) и www.
	protoRelRe = regexp.MustCompile(`(^|[\s("'=\]])//([\p{L}\p{N}-]+\.)`)
	wwwRe      = regexp.MustCompile(`(?i)\bwww\.`)
	// Markdown-ссылки и картинки (в том числе без схемы: [y](evil.example/z))
	// и HTML-теги: разрываем синтаксис, текст остаётся читаемым.
	mdLinkRe  = regexp.MustCompile(`\]\(`)
	htmlTagRe = regexp.MustCompile(`<([A-Za-z!/])`)

	// Тексты ошибок ClickHouse цитируют данные: «before: '…'», «('…')».
	chBeforeRe = regexp.MustCompile(`(?s)(before: ).*`)
	// Обратные кавычки — идентификаторы ClickHouse, в них тоже бывают данные.
	quotedRe = regexp.MustCompile("'[^']*'|\"[^\"]*\"|«[^»]*»|`[^`]*`")

	// Узел, похожий на машину человека: ws-ivanov, ivanov-pc.
	personHostRe = regexp.MustCompile(`(?i)^(?:ws|pc|nb|wks|laptop|desktop|notebook|mbp|macbook|user)[-_.]?[\p{L}]{3,}|[\p{L}]{3,}[-_.](?:ws|pc|nb|wks|laptop|desktop|notebook|mbp|macbook)(?:[-_.]?\d+)?$`)
)

// Имена ключей с признаком секрета, значения которых секретом не являются:
// идентификаторы и типы (token_id, secret_name, token_rotated…).
var notSecretSuffixes = []string{"_id", "-id", ".id", "id", "_name", "-name", ".name", "name", "_type", "type", "_rotated", "_revoked", "_count", "_ttl", "_expires_at", "_len"}

// pathValue — значение ключа-каталога (PWD=/root, OLDPWD=/home/x из строки
// sudo): «pwd» здесь — текущий каталог, а не пароль.
func pathValue(k, v string) bool {
	return strings.HasSuffix(strings.ToLower(k), "pwd") && strings.HasPrefix(v, "/")
}

func notSecretKey(k string) bool {
	k = strings.ToLower(k)
	// Метка нашей же редакции: «[REDACTED:…]» не секрет.
	if strings.HasPrefix(k, "redacted") {
		return true
	}
	for _, s := range notSecretSuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// Secrets — удаление секретов и канареек; остальной текст не меняется.
func (r *Redactor) Secrets(s string) string {
	if s == "" {
		return s
	}
	s = privateKeyRe.ReplaceAllStringFunc(s, func(m string) string { return "[REDACTED:pem-" + r.Fingerprint(m) + "]" })
	s = urlCredsRe.ReplaceAllString(s, "${1}[REDACTED]@")
	s = knownTokenRe.ReplaceAllStringFunc(s, r.secretMark)
	for _, re := range []*regexp.Regexp{bearerRe, authSchemeRe} {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			g := re.FindStringSubmatch(m)
			if strings.HasPrefix(g[3], "[REDACTED") {
				return m
			}
			return g[1] + g[2] + r.secretMark(g[3])
		})
	}
	s = urlParamRe.ReplaceAllStringFunc(s, func(m string) string {
		g := urlParamRe.FindStringSubmatch(m)
		if strings.HasPrefix(g[2], "[REDACTED") {
			return m
		}
		return g[1] + r.secretMark(g[2])
	})
	// Группы ключей: 1 — граница, 2 — имя, 3 — разделитель, 4 — значение.
	s = keyQuotedRe.ReplaceAllStringFunc(s, func(m string) string {
		g := keyQuotedRe.FindStringSubmatch(m)
		inner := g[4][1 : len(g[4])-1]
		if notSecretKey(g[2]) || inner == "" || strings.HasPrefix(inner, "[REDACTED") || pathValue(g[2], inner) {
			return m
		}
		q := g[4][:1]
		return g[1] + g[2] + g[3] + q + r.secretMark(inner) + q
	})
	s = keyValueRe.ReplaceAllStringFunc(s, func(m string) string {
		g := keyValueRe.FindStringSubmatch(m)
		if notSecretKey(g[2]) || strings.HasPrefix(g[4], "[REDACTED") || pathValue(g[2], g[4]) {
			return m
		}
		// «token rotated», «password changed» — разделитель-пробел допустим
		// только перед значением, похожим на секрет (цифры или длинное). У
		// русского имени («с паролем Hunter2Hunter2») — буквы и цифры от 8
		// символов: «ключ найден» не секрет.
		if strings.TrimSpace(g[3]) == "" && !secretLike(g[4]) && !(cyrillicKey(g[2]) && lettersAndDigits(g[4])) {
			return m
		}
		return g[1] + g[2] + g[3] + r.secretMark(g[4])
	})
	s = dashPRe.ReplaceAllStringFunc(s, func(m string) string {
		g := dashPRe.FindStringSubmatch(m)
		if strings.IndexFunc(g[2], unicode.IsLetter) < 0 || strings.HasPrefix(g[2], "[REDACTED") {
			return m // -p8080:80 — порт, не пароль
		}
		return g[1] + "-p" + r.secretMark(g[2])
	})
	s = canaryRe.ReplaceAllString(s, "[REDACTED:canary]")
	if len(r.canaries) > 0 {
		low := strings.ToLower(s)
		for _, c := range r.canaries {
			for {
				i := strings.Index(low, c)
				if i < 0 {
					break
				}
				s = s[:i] + "[REDACTED:canary]" + s[i+len(c):]
				low = strings.ToLower(s)
			}
		}
	}
	return s
}

// blobLike — base64-подобная строка со всеми тремя классами символов.
func blobLike(v string) bool {
	var up, low, dig bool
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			low = true
		case c >= '0' && c <= '9':
			dig = true
		}
	}
	return up && low && dig
}

// replaceWord заменяет вхождения old, не окружённые буквами, цифрами и «_»,
// без учёта регистра: субъект «root» не превращает «rootkit» в «subj-…kit»,
// а «A.Sidorova» и «a.sidorova» — один субъект.
func replaceWord(s, old, repl string) string {
	if old == "" {
		return s
	}
	locs := wordRe(old).FindAllStringIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	prev := 0
	for _, l := range locs {
		before, _ := utf8.DecodeLastRuneInString(s[:l[0]])
		after, _ := utf8.DecodeRuneInString(s[l[1]:])
		if (l[0] > 0 && wordRune(before)) || (l[1] < len(s) && wordRune(after)) {
			continue
		}
		b.WriteString(s[prev:l[0]])
		b.WriteString(repl)
		prev = l[1]
	}
	b.WriteString(s[prev:])
	return b.String()
}

// wordRes — скомпилированные шаблоны слов replaceWord (субъекты и словарь
// повторяются от вызова к вызову); при переполнении кэш сбрасывается.
var (
	wordResMu sync.Mutex
	wordRes   = map[string]*regexp.Regexp{}
)

const maxWordRes = 10_000

func wordRe(w string) *regexp.Regexp {
	wordResMu.Lock()
	defer wordResMu.Unlock()
	if re, ok := wordRes[w]; ok {
		return re
	}
	if len(wordRes) >= maxWordRes {
		wordRes = map[string]*regexp.Regexp{}
	}
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(w))
	wordRes[w] = re
	return re
}

func wordRune(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

// cyrillicKey — имя ключа русское (пароль, токен, секрет, ключ).
func cyrillicKey(k string) bool {
	return strings.IndexFunc(k, func(c rune) bool { return unicode.Is(unicode.Cyrillic, c) }) >= 0
}

// lettersAndDigits — не короче 8 символов, есть и буквы, и цифры.
func lettersAndDigits(v string) bool {
	return utf8.RuneCountInString(v) >= 8 && strings.IndexFunc(v, unicode.IsLetter) >= 0 && strings.IndexFunc(v, unicode.IsDigit) >= 0
}

// secretLike — значение после пробела похоже на секрет: не короче 16
// символов и с цифрами, а не слово естественного языка.
func secretLike(v string) bool {
	if len(v) < 16 {
		return false
	}
	return strings.ContainsAny(v, "0123456789")
}

// Text — секреты, затем (если включено) ПДн и обезвреживание ссылок.
func (r *Redactor) Text(s string) string {
	return r.text(s, nil)
}

// TextWith — Text, где известные субъекты (их исходные значения) в тексте
// тоже заменяются псевдонимами: строка цепочки повторяет логин субъекта.
func (r *Redactor) TextWith(s string, subjects ...string) string {
	var known []string
	for _, x := range subjects {
		if x = strings.TrimSpace(x); utf8.RuneCountInString(x) >= 3 {
			known = append(known, x)
		}
	}
	sort.Slice(known, func(i, j int) bool { return len(known[i]) > len(known[j]) })
	return r.text(s, known)
}

// Leaks — в тексте есть то, что редакция убрала бы без изменения формы
// остального: секрет, канарейка, известный субъект или имя из словаря
// (словом). Для проверки готового текста, где псевдонимы и обезвреженные
// ссылки уже допустимы и Text сравнивать нельзя.
func (r *Redactor) Leaks(s string, subjects ...string) bool {
	if r.Secrets(s) != s {
		return true
	}
	for _, list := range [][]string{subjects, r.names, r.nameWords} {
		for _, n := range list {
			if n = strings.TrimSpace(n); utf8.RuneCountInString(n) >= 3 && replaceWord(s, n, "\x00") != s {
				return true
			}
		}
	}
	return false
}

// ErrorText — текст ошибки консоли/ClickHouse: всё, что процитировано
// («before: '…'», «('…')», "…"), скрывается целиком — там данные запроса и
// строк, а не диагностика. Остальное — как Text.
func (r *Redactor) ErrorText(s string, subjects ...string) string {
	s = chBeforeRe.ReplaceAllString(s, "${1}[скрыто]")
	s = quotedRe.ReplaceAllString(s, "'[скрыто]'")
	return r.TextWith(s, subjects...)
}

// Host — имя узла: похожее на машину человека (ws-ivanov, ivanov-pc, имя
// из словаря или логин известного субъекта внутри) — псевдонимом host-…,
// остальное — как Text. Без Pseudonymize — Text.
func (r *Redactor) Host(s string, subjects ...string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" || !r.pseudo {
		return r.TextWith(s, subjects...)
	}
	if r.personHost(s, subjects) {
		p := "host-" + r.mac("host", s, 10)
		r.remember(p, s)
		return p
	}
	out := r.TextWith(s, subjects...)
	if out == s {
		r.remember(shownHostKey+s, s)
	}
	return out
}

// shownHostKey — префикс записи «узел выдан открытым» в обратном словаре
// (не путается с псевдонимами: в них нет «:»).
const shownHostKey = "shown-host:"

// ShownHost — узел этот процесс выдал открытым (Host не заменил его
// псевдонимом при известных субъектах документа). Для точного фильтра в
// triage: имя, которого модель не видела, — догадка, и по total она
// подтверждала бы, что узел srv-<фамилия> существует.
func (r *Redactor) ShownHost(s string) bool {
	s = strings.TrimSpace(s)
	v, ok := r.Resolve(shownHostKey + s)
	return ok && v == s
}

func (r *Redactor) personHost(s string, subjects []string) bool {
	if personHostRe.MatchString(s) {
		return true
	}
	low := strings.ToLower(s)
	for _, n := range r.names {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	for _, subj := range subjects {
		// логин i.ivanov → фамилия «ivanov» в имени узла
		for _, part := range strings.FieldsFunc(strings.ToLower(subj), func(c rune) bool { return !unicode.IsLetter(c) }) {
			if utf8.RuneCountInString(part) >= 4 && strings.Contains(low, part) {
				return true
			}
		}
	}
	return false
}

// PersonHost — узел будет заменён псевдонимом даже без субъектов документа
// (по виду или словарю). Логин субъекта внутри имени (srv-sidorova) так не
// виден — для фильтра в triage нужен ShownHost.
func (r *Redactor) PersonHost(s string) bool {
	return r.pseudo && r.personHost(strings.TrimSpace(s), nil)
}

// hostPseudonymRe — вид псевдонима узла.
var hostPseudonymRe = regexp.MustCompile(`^host-[0-9a-f]{10}$`)

// IsHostPseudonym — строка выглядит как псевдоним узла.
func IsHostPseudonym(s string) bool { return hostPseudonymRe.MatchString(strings.TrimSpace(s)) }

func (r *Redactor) text(s string, subjects []string) string {
	s = r.Secrets(s)
	if s == "" {
		return s
	}
	if r.pseudo {
		s = blobRe.ReplaceAllStringFunc(s, func(m string) string {
			if !blobLike(m) {
				return m
			}
			return r.secretMark(m)
		})
		s = subjectKVRe.ReplaceAllStringFunc(s, func(m string) string {
			g := subjectKVRe.FindStringSubmatch(m)
			if strings.HasPrefix(g[3], "[REDACTED") {
				return m
			}
			// Значение вида subj-… тоже хешируется: подделка псевдонима.
			return g[1] + g[2] + r.Subject(g[3])
		})
		s = loginTextRe.ReplaceAllStringFunc(s, func(m string) string {
			g := loginTextRe.FindStringSubmatch(m)
			return g[1] + r.Subject(g[2])
		})
		s = tildeHomeRe.ReplaceAllStringFunc(s, func(m string) string {
			g := tildeHomeRe.FindStringSubmatch(m)
			return g[1] + "~" + r.Subject(g[2])
		})
		s = emailRe.ReplaceAllStringFunc(s, func(m string) string {
			g := emailRe.FindStringSubmatch(m)
			domain := strings.ToLower(dotWordRe.ReplaceAllString(g[3], "."))
			// « at » — и обычный английский («uploaded at host.example»):
			// адресом считается, только если локальная часть похожа на
			// логин (точка, «_», цифры) или домен записан словами «dot».
			if strings.EqualFold(strings.TrimSpace(g[2]), "at") && !strings.ContainsAny(g[1], "._0123456789") && domain == strings.ToLower(g[3]) {
				return m
			}
			return r.Subject(strings.ToLower(g[1])+"@"+domain) + "@" + domain
		})
		s = phoneRe.ReplaceAllStringFunc(s, func(m string) string {
			digits := 0
			for _, c := range m {
				if c >= '0' && c <= '9' {
					digits++
				}
			}
			if digits < 10 {
				return m
			}
			return "[phone:" + r.mac("phone", m, 8) + "]"
		})
		s = homeDirRe.ReplaceAllStringFunc(s, func(m string) string {
			g := homeDirRe.FindStringSubmatch(m)
			return g[1] + r.Subject(g[2])
		})
		for _, n := range subjects {
			s = replaceWord(s, n, r.Subject(n))
		}
		for _, n := range r.names {
			// Словарь — без учёта регистра; псевдоним — от формы из словаря.
			s = replaceWord(s, n, r.Subject(n))
		}
		for _, w := range r.nameWords {
			s = replaceWord(s, w, r.Subject(w))
		}
	}
	if r.defang {
		s = httpRe.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasPrefix(strings.ToLower(m), "https") {
				return "hxxps://"
			}
			return "hxxp://"
		})
		s = schemeRe.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasPrefix(strings.ToLower(m), "hxxp") {
				return m
			}
			return m[:len(m)-3] + "[:]//"
		})
		s = scriptRe.ReplaceAllString(s, "${1}[:]")
		s = protoRelRe.ReplaceAllString(s, "${1}[//]${2}")
		s = wwwRe.ReplaceAllStringFunc(s, func(m string) string { return m[:3] + "[.]" })
		s = mdLinkRe.ReplaceAllString(s, "] (")
		s = htmlTagRe.ReplaceAllString(s, "‹${1}")
	}
	return s
}
