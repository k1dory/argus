// Package pull — источники, которые надо опрашивать: CrowdStrike Falcon
// Streaming API и объектные хранилища S3 (Yandex Cloud Audit Trails, VK Cloud).
package pull

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// FalconConfig — CrowdStrike Falcon: OAuth2 client credentials, discovery
// потоков (datafeed/v2), чтение JSON-событий построчно.
type FalconConfig struct {
	BaseURL      string `yaml:"base_url"` // https://api.crowdstrike.com | api.eu-1.crowdstrike.com
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"` // ${FALCON_CLIENT_SECRET}
	AppID        string `yaml:"app_id"`        // имя потребителя потока, ≤ 32 символов
}

type falconEvent struct {
	Metadata struct {
		EventType         string `json:"eventType"`
		EventCreationTime int64  `json:"eventCreationTime"`
		Offset            int64  `json:"offset"`
	} `json:"metadata"`
	Event map[string]any `json:"event"`
}

// ParseFalconEvent — DetectionSummaryEvent, UserActivityAuditEvent, AuthActivityAuditEvent …
func ParseFalconEvent(line []byte) (model.Event, error) {
	var fe falconEvent
	if err := json.Unmarshal(line, &fe); err != nil || fe.Metadata.EventType == "" {
		return model.Event{}, fmt.Errorf("falcon: не событие потока")
	}
	str := func(k string) string {
		if v, ok := fe.Event[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	e := model.Event{
		Source: "edr.crowdstrike", SourceClass: "edr", Vendor: "CrowdStrike", Product: "Falcon",
		Raw: string(line), Attrs: map[string]string{"event_type": fe.Metadata.EventType, "offset": fmt.Sprint(fe.Metadata.Offset)},
	}
	if fe.Metadata.EventCreationTime > 0 {
		e.TS = model.FormatTS(time.UnixMilli(fe.Metadata.EventCreationTime).UTC())
	}
	switch fe.Metadata.EventType {
	case "DetectionSummaryEvent":
		e.Action, e.Outcome = "threat.detect", "detected"
		e.Node = str("ComputerName")
		e.ActorName = str("UserName")
		e.Object = strings.TrimSpace(str("FilePath") + " " + str("FileName"))
		e.SrcIP = str("LocalIP")
		for _, k := range []string{"DetectName", "DetectDescription", "Tactic", "Technique", "CommandLine", "ParentImageFileName", "SHA256String", "Severity", "SeverityName", "FalconHostLink"} {
			if v := str(k); v != "" {
				e.Attrs[strings.ToLower(k)] = v
			}
		}
		e.Attrs["name"] = str("DetectName") + " · " + str("DetectDescription")
		switch str("SeverityName") {
		case "Critical":
			e.Severity = 10
		case "High":
			e.Severity = 8
		case "Medium":
			e.Severity = 5
		case "Low":
			e.Severity = 3
		default:
			e.Severity = 2
		}
	case "UserActivityAuditEvent", "AuthActivityAuditEvent":
		e.Action = "falcon." + strings.ToLower(strings.TrimSpace(str("OperationName")))
		e.ActorName = str("UserId")
		e.SrcIP = str("UserIp")
		e.Object = str("ServiceName")
		e.Outcome = "success"
		if strings.EqualFold(str("Success"), "false") {
			e.Outcome, e.Severity = "failure", 5
		}
		e.Attrs["operation"] = str("OperationName")
	case "IncidentSummaryEvent":
		e.Action, e.Outcome, e.Severity = "threat.incident", "detected", 8
		e.Object = str("IncidentId")
		e.Attrs["state"] = str("State")
		e.Attrs["fine_score"] = str("FineScore")
	default:
		e.Action = "falcon." + strings.ToLower(fe.Metadata.EventType)
	}
	if e.ActorName != "" {
		e.ActorKind = "user"
		if strings.HasSuffix(e.ActorName, "$") || strings.Contains(strings.ToLower(e.ActorName), "system") {
			e.ActorKind = "system"
		}
	}
	e.Ensure()
	return e, nil
}

type Falcon struct {
	cfg  FalconConfig
	http *http.Client
	Emit func(model.Event)
	// Delay — первая пауза перед переподключением (далее удваивается до 2 минут);
	// 0 — 5 секунд. Поле, а не константа, чтобы тесты не ждали реального времени.
	Delay time.Duration
}

func NewFalcon(cfg FalconConfig, emit func(model.Event)) *Falcon {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.crowdstrike.com"
	}
	if cfg.AppID == "" {
		cfg.AppID = "argus"
	}
	return &Falcon{cfg: cfg, http: &http.Client{Timeout: 0}, Emit: emit}
}

func (f *Falcon) token(ctx context.Context) (string, error) {
	form := url.Values{"client_id": {f.cfg.ClientID}, "client_secret": {f.cfg.ClientSecret}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(f.cfg.BaseURL, "/")+"/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("falcon oauth: %s", resp.Status)
	}
	return out.AccessToken, nil
}

type falconStream struct {
	DataFeedURL  string `json:"dataFeedURL"`
	SessionToken struct {
		Token string `json:"token"`
	} `json:"sessionToken"`
}

// Run — бесконечный цикл: discover → read stream → reconnect с паузой.
func (f *Falcon) Run(ctx context.Context) {
	if f.cfg.ClientID == "" || f.cfg.ClientSecret == "" {
		slog.Warn("falcon: client_id/client_secret не заданы — источник выключен")
		return
	}
	delay := f.Delay
	if delay <= 0 {
		delay = 5 * time.Second
	}
	for ctx.Err() == nil {
		if err := f.once(ctx); err != nil {
			slog.Warn("falcon", "err", err, "retry_in", delay)
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		if delay < 2*time.Minute {
			delay *= 2
		}
	}
}

func (f *Falcon) once(ctx context.Context) error {
	tok, err := f.token(ctx)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(f.cfg.BaseURL, "/")+"/sensors/entities/datafeed/v2?appId="+url.QueryEscape(f.cfg.AppID), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	var disc struct {
		Resources []falconStream `json:"resources"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &disc) != nil || len(disc.Resources) == 0 {
		return fmt.Errorf("falcon discover: %s %s", resp.Status, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	st := disc.Resources[0]
	sreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, st.DataFeedURL, nil)
	sreq.Header.Set("Authorization", "Token "+st.SessionToken.Token)
	sreq.Header.Set("Accept", "application/json")
	sresp, err := f.http.Do(sreq)
	if err != nil {
		return err
	}
	defer sresp.Body.Close()
	slog.Info("falcon stream connected")
	sc := bufio.NewScanner(sresp.Body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if e, err := ParseFalconEvent([]byte(line)); err == nil {
			f.Emit(e)
		}
	}
	return fmt.Errorf("falcon stream closed: %v", sc.Err())
}
