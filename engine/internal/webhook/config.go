package webhook

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// TargetConfig — цель в argus.analyst.yml (notify.webhooks). Адрес, секрет и
// токен задаются ИМЕНАМИ переменных окружения: значения в конфиг не попадают.
type TargetConfig struct {
	Name         string   `yaml:"name"`
	Kind         string   `yaml:"kind"`      // webhook (единственный встроенный вид; пусто — webhook)
	MinLevel     string   `yaml:"min_level"` // critical | high | medium | low; по умолчанию high
	Events       []string `yaml:"events"`    // incident.created, incident.escalated; пусто — оба
	IncludeChain bool     `yaml:"include_chain"`
	AllowHTTP    bool     `yaml:"allow_http"` // разрешить http:// (иначе только https)
	URLEnv       string   `yaml:"url_env"`
	SecretEnv    string   `yaml:"secret_env"` // секрет HMAC подписи тела
	TokenEnv     string   `yaml:"token_env"`  // Bearer (необязательно)
}

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	envNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// Build собирает цели. Цель с пустым адресом в окружении выключена без
// ошибки (так стенд стартует с примером конфига); ошибка конфигурации
// выключает только свою цель. Сообщения не содержат значений переменных.
func Build(cfgs []TargetConfig, getenv func(string) string) (routes []*Route, problems []string) {
	seen := map[string]bool{}
	for i, c := range cfgs {
		name := strings.TrimSpace(c.Name)
		if !nameRe.MatchString(name) {
			problems = append(problems, fmt.Sprintf("notify.webhooks[%d]: имя %q — латиница в нижнем регистре, цифры, - и _, до 40 символов", i, c.Name))
			continue
		}
		if seen[name] {
			problems = append(problems, fmt.Sprintf("notify.webhooks %s: имя повторяется", name))
			continue
		}
		seen[name] = true
		r, enabled, err := buildOne(name, c, getenv)
		if err != nil {
			problems = append(problems, fmt.Sprintf("notify.webhooks %s: %v", name, err))
			continue
		}
		if enabled {
			routes = append(routes, r)
		}
	}
	return routes, problems
}

func buildOne(name string, c TargetConfig, getenv func(string) string) (*Route, bool, error) {
	minLevel := strings.ToLower(strings.TrimSpace(c.MinLevel))
	if minLevel == "" {
		minLevel = "high"
	}
	if levelRank(minLevel) == 0 {
		return nil, false, fmt.Errorf("min_level %q: ожидается critical, high, medium или low", c.MinLevel)
	}
	for _, e := range c.Events {
		if e != EventCreated && e != EventEscalated {
			return nil, false, fmt.Errorf("events: неизвестное событие %q", e)
		}
	}
	for field, env := range map[string]string{"url_env": c.URLEnv, "secret_env": c.SecretEnv, "token_env": c.TokenEnv} {
		if env != "" && !envNameRe.MatchString(env) {
			return nil, false, fmt.Errorf("%s: нужно имя переменной окружения, а не значение", field)
		}
	}
	if c.URLEnv == "" {
		return nil, false, fmt.Errorf("url_env не задан")
	}
	raw := strings.TrimSpace(getenv(c.URLEnv))
	if raw == "" {
		return nil, false, nil // выключена: адрес не задан
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http")) {
		return nil, false, fmt.Errorf("%s: нужен https-адрес без логина в URL (http — только с allow_http: true)", c.URLEnv)
	}
	r := &Route{Name: name, MinLevel: minLevel, Events: c.Events, IncludeChain: c.IncludeChain}
	switch c.Kind {
	case "webhook", "":
		secret := getenv(c.SecretEnv)
		if c.SecretEnv == "" || len(secret) < 32 {
			return nil, false, fmt.Errorf("secret_env: нужен секрет HMAC не короче 32 символов")
		}
		r.Target = &HTTPTarget{Name: name, URL: raw, Secret: secret, Token: envOrEmpty(getenv, c.TokenEnv), HTTP: newHTTPClient()}
	default:
		return nil, false, fmt.Errorf("kind %q: ожидается webhook", c.Kind)
	}
	return r, true, nil
}

func envOrEmpty(getenv func(string) string, name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSpace(getenv(name))
}
