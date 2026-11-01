package pull

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// S3Config — опрос объектного хранилища: Yandex Cloud Audit Trails (экспорт в
// Object Storage), VK Cloud audit logs, любой NDJSON единой схемы в бакете.
type S3Config struct {
	Name      string `yaml:"name"`     // имя источника: cloud.yandex
	Endpoint  string `yaml:"endpoint"` // https://storage.yandexcloud.net | https://hb.vkcs.cloud
	Region    string `yaml:"region"`   // ru-central1
	Bucket    string `yaml:"bucket"`
	Prefix    string `yaml:"prefix"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"` // ${S3_SECRET_KEY}
	Format    string `yaml:"format"`     // yandex-audit | events (NDJSON единой схемы)
	Interval  string `yaml:"interval"`   // 60s
	StateFile string `yaml:"state_file"` // последний обработанный ключ
}

type S3 struct {
	cfg  S3Config
	http *http.Client
	Emit func(model.Event)
	// Объект, чтение которого оборвалось: сколько строк уже выдано и сколько было
	// попыток. Повтор пропускает выданные строки — событие не дублируется.
	retryKey   string
	retryDone  int
	retryCount int
	// Skipped — объектов, брошенных из-за битого содержимого (gzip, CRC, строка
	// длиннее 32 МиБ) или после s3MaxAttempts неудачных чтений.
	Skipped atomic.Int64
}

// s3MaxAttempts — сколько раз читать объект, тело которого обрывается посреди:
// дальше он считается битым, курсор идёт дальше. Иначе один испорченный объект
// навсегда останавливал бы чтение бакета. Отказ хранилища на сам GET (403, 5xx,
// сеть) попыткой не считается: это не объект битый, а доступ — повтор без предела,
// как раньше; 404 (объект удалён после листинга) — пропуск.
const s3MaxAttempts = 3

// s3ContentError — ошибка самого содержимого: повтор не поможет.
func s3ContentError(err error) bool {
	return errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.Is(err, bufio.ErrTooLong)
}

func NewS3(cfg S3Config, emit func(model.Event)) *S3 {
	if cfg.Region == "" {
		cfg.Region = "ru-central1"
	}
	if cfg.Format == "" {
		cfg.Format = "events"
	}
	if cfg.Name == "" {
		cfg.Name = "cloud." + cfg.Format
	}
	return &S3{cfg: cfg, http: &http.Client{Timeout: 5 * time.Minute}, Emit: emit}
}

// sign — AWS SigV4 (только стандартная библиотека), достаточно для GET/List.
func (s *S3) sign(req *http.Request, payloadHash string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("host", req.URL.Host)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	var canonHeaders strings.Builder
	for _, h := range signed {
		canonHeaders.WriteString(h + ":" + strings.TrimSpace(req.Header.Get(h)) + "\n")
	}
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonQuery []string
	for _, k := range keys {
		canonQuery = append(canonQuery, url.QueryEscape(k)+"="+url.QueryEscape(q.Get(k)))
	}
	canonical := strings.Join([]string{req.Method, req.URL.EscapedPath(), strings.Join(canonQuery, "&"),
		canonHeaders.String(), strings.Join(signed, ";"), payloadHash}, "\n")
	scope := date + "/" + s.cfg.Region + "/s3/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hexSHA(canonical)}, "\n")
	k := hmacSHA([]byte("AWS4"+s.cfg.SecretKey), date)
	k = hmacSHA(k, s.cfg.Region)
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.cfg.AccessKey, scope, strings.Join(signed, ";"), sig))
}

func hexSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func (s *S3) get(ctx context.Context, path string, query url.Values) (*http.Response, error) {
	u := strings.TrimRight(s.cfg.Endpoint, "/") + "/" + s.cfg.Bucket + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	s.sign(req, hexSHA(""))
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		resp.Body.Close()
		return nil, &s3StatusError{code: resp.StatusCode, msg: fmt.Sprintf("s3 %s: %s", resp.Status, strings.TrimSpace(string(body)))}
	}
	return resp, nil
}

// s3StatusError — GET объекта не дал тела: ответ хранилища не 200 (нет прав, сбой,
// объекта нет; code — статус) или сетевая ошибка (code 0, err — причина).
type s3StatusError struct {
	code int
	msg  string
	err  error
}

func (e *s3StatusError) Error() string { return e.msg }
func (e *s3StatusError) Unwrap() error { return e.err }

func (e *s3StatusError) isNotFound() bool { return e != nil && e.code == http.StatusNotFound }

type listResult struct {
	Contents []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		Size         int64  `xml:"Size"`
	} `xml:"Contents"`
	IsTruncated bool `xml:"IsTruncated"`
}

func (s *S3) list(ctx context.Context, startAfter string) (listResult, error) {
	q := url.Values{"list-type": {"2"}, "max-keys": {"1000"}}
	if s.cfg.Prefix != "" {
		q.Set("prefix", s.cfg.Prefix)
	}
	if startAfter != "" {
		q.Set("start-after", startAfter)
	}
	resp, err := s.get(ctx, "", q)
	if err != nil {
		return listResult{}, err
	}
	defer resp.Body.Close()
	var lr listResult
	return lr, xml.NewDecoder(resp.Body).Decode(&lr)
}

func (s *S3) Run(ctx context.Context) {
	if s.cfg.AccessKey == "" || s.cfg.SecretKey == "" || s.cfg.Bucket == "" {
		slog.Warn("s3: access_key/secret_key/bucket не заданы — источник выключен", "name", s.cfg.Name)
		return
	}
	interval, _ := time.ParseDuration(s.cfg.Interval)
	if interval <= 0 {
		interval = time.Minute
	}
	last := s.loadState()
	for ctx.Err() == nil {
		lr, err := s.list(ctx, last)
		if err != nil {
			slog.Warn("s3 list", "name", s.cfg.Name, "err", err)
		} else {
			for _, obj := range lr.Contents {
				if obj.Size == 0 {
					last = obj.Key
					continue
				}
				skip := 0
				if obj.Key == s.retryKey {
					skip = s.retryDone
				}
				done, n, err := s.fetchFrom(ctx, obj.Key, skip)
				var st *s3StatusError
				if errors.As(err, &st) && st.code != http.StatusNotFound {
					// Тела нет — доступ или сеть: повтор на следующем цикле без счёта попыток.
					slog.Warn("s3 fetch", "key", obj.Key, "err", err)
					break
				}
				if err != nil && !st.isNotFound() && ctx.Err() == nil && !s3ContentError(err) {
					if obj.Key != s.retryKey {
						s.retryKey, s.retryCount = obj.Key, 0
					}
					s.retryDone, s.retryCount = done, s.retryCount+1
					if s.retryCount < s3MaxAttempts {
						slog.Warn("s3 fetch: повтор на следующем цикле", "key", obj.Key, "events", n, "attempt", s.retryCount, "err", err)
						break
					}
				}
				if err != nil && ctx.Err() != nil {
					return // остановка посреди объекта — дочитаем после рестарта, курсор не двигаем
				}
				if err != nil {
					s.Skipped.Add(1)
					slog.Error("s3: объект прочитан не целиком и пропущен — выданные события остаются, курсор идёт дальше", "name", s.cfg.Name, "key", obj.Key, "events", n, "err", err)
				} else {
					slog.Info("s3 object", "name", s.cfg.Name, "key", obj.Key, "events", n)
				}
				s.retryKey, s.retryDone, s.retryCount = "", 0, 0
				last = obj.Key
				s.saveState(last)
			}
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return
		}
	}
}

// fetch — все события объекта (без пропуска уже выданных).
func (s *S3) fetch(ctx context.Context, key string) (int, error) {
	_, n, err := s.fetchFrom(ctx, key, 0)
	return n, err
}

// fetchFrom выдаёт события объекта, пропуская первые skip непустых строк (уже
// выданные прошлой попыткой). done — сколько непустых строк пройдено всего (для
// следующей попытки), n — сколько событий выдано в этот раз.
func (s *S3) fetchFrom(ctx context.Context, key string, skip int) (done, n int, err error) {
	resp, err := s.get(ctx, "/"+strings.TrimLeft(key, "/"), nil)
	if err != nil {
		var st *s3StatusError
		if !errors.As(err, &st) {
			err = &s3StatusError{msg: err.Error(), err: err}
		}
		return skip, 0, err
	}
	defer resp.Body.Close()
	// Экспорт в бакет бывает сжатым (*.json.gz): распознаём по магическим байтам,
	// а не по имени ключа — иначе такой объект молча давал бы 0 событий.
	br := bufio.NewReader(resp.Body)
	var body io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return skip, 0, fmt.Errorf("gzip %s: %w", key, err)
		}
		defer gz.Close()
		body = gz
	}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	lastEmitted := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		done++
		lastEmitted = false
		if done <= skip {
			continue
		}
		var e model.Event
		var err error
		switch s.cfg.Format {
		case "yandex-audit":
			e, err = ParseYandexAudit([]byte(line))
		default:
			err = json.Unmarshal([]byte(line), &e)
		}
		if err != nil {
			continue
		}
		if e.Source == "" {
			e.Source = s.cfg.Name
		}
		e.Ensure()
		s.Emit(e)
		n++
		lastEmitted = true
	}
	if err := sc.Err(); err != nil {
		// При ошибке чтения Scanner отдаёт обрывок последней строки отдельным токеном:
		// если он не стал событием, следующая попытка должна прочитать эту строку целиком.
		if !lastEmitted && done > skip {
			done--
		}
		return max(done, skip), n, err
	}
	return max(done, skip), n, nil
}

func (s *S3) loadState() string {
	if s.cfg.StateFile == "" {
		return ""
	}
	b, _ := os.ReadFile(s.cfg.StateFile)
	return strings.TrimSpace(string(b))
}

func (s *S3) saveState(key string) {
	if s.cfg.StateFile != "" {
		_ = os.WriteFile(s.cfg.StateFile, []byte(key), 0o600)
	}
}

/* ===== Yandex Cloud Audit Trails: одна запись = одна строка JSON =====
   {event_id, event_source, event_type, event_time, authentication{subject_type, subject_name, subject_id},
    authorization{authorized}, resource_metadata{path[]}, request_metadata{remote_address, user_agent},
    event_status, details{...}, ...} */

type yandexAudit struct {
	EventID        string `json:"event_id"`
	EventSource    string `json:"event_source"`
	EventType      string `json:"event_type"`
	EventTime      string `json:"event_time"`
	EventStatus    string `json:"event_status"`
	Authentication struct {
		SubjectType string `json:"subject_type"`
		SubjectName string `json:"subject_name"`
		SubjectID   string `json:"subject_id"`
	} `json:"authentication"`
	Authorization struct {
		Authorized bool `json:"authorized"`
	} `json:"authorization"`
	ResourceMetadata struct {
		Path []struct {
			ResourceType string `json:"resource_type"`
			ResourceID   string `json:"resource_id"`
			ResourceName string `json:"resource_name"`
		} `json:"path"`
	} `json:"resource_metadata"`
	RequestMetadata struct {
		RemoteAddress string `json:"remote_address"`
		UserAgent     string `json:"user_agent"`
	} `json:"request_metadata"`
	Details map[string]any `json:"details"`
}

func ParseYandexAudit(line []byte) (model.Event, error) {
	var a yandexAudit
	if err := json.Unmarshal(line, &a); err != nil || a.EventType == "" {
		return model.Event{}, fmt.Errorf("yandex audit: не запись Audit Trails")
	}
	e := model.Event{
		Source: "cloud.yandex", SourceClass: "k8s", Vendor: "Yandex Cloud", Product: a.EventSource,
		Action:    "yc." + strings.ToLower(strings.TrimPrefix(a.EventType, "yandex.cloud.audit.")),
		ActorName: a.Authentication.SubjectName, SessionID: a.EventID,
		SrcIP: a.RequestMetadata.RemoteAddress, Raw: string(line),
		Attrs: map[string]string{"event_source": a.EventSource, "user_agent": a.RequestMetadata.UserAgent, "subject_id": a.Authentication.SubjectID},
	}
	if t, err := time.Parse(time.RFC3339Nano, a.EventTime); err == nil {
		e.TS = model.FormatTS(t)
	}
	switch a.Authentication.SubjectType {
	case "SERVICE_ACCOUNT":
		e.ActorKind = "service"
	case "YANDEX_PASSPORT_USER_ACCOUNT", "FEDERATED_USER_ACCOUNT":
		e.ActorKind = "user"
	default:
		e.ActorKind = "unknown"
	}
	var path []string
	for _, p := range a.ResourceMetadata.Path {
		path = append(path, p.ResourceType+"/"+firstNonEmpty(p.ResourceName, p.ResourceID))
	}
	e.Object = strings.Join(path, "/")
	switch {
	case !a.Authorization.Authorized:
		e.Outcome, e.Severity = "deny", 6
	case strings.EqualFold(a.EventStatus, "ERROR"):
		e.Outcome, e.Severity = "failure", 3
	default:
		e.Outcome = "success"
	}
	lt := strings.ToLower(a.EventType)
	if strings.Contains(lt, "accessbinding") || strings.Contains(lt, "setaccessbindings") || strings.Contains(lt, "updateaccessbindings") {
		e.Severity = max(e.Severity, 6)
		e.Attrs["iam_change"] = "true"
	}
	if strings.Contains(lt, "delete") {
		e.Severity = max(e.Severity, 5)
	}
	e.Ensure()
	return e, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
