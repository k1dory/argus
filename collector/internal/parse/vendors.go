package parse

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

/* ===== Squid native access.log (через syslog или /ingest/syslog) =====
   ts.ms elapsed client code/status bytes method url user hier/peer type */

var squidRe = regexp.MustCompile(`^(\d{10}(?:\.\d{3})?)\s+(\d+)\s+(\S+)\s+([A-Z_]+)/(\d{3})\s+(\d+)\s+([A-Z]+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)`)

// ParseSquid распознаёт строку native-формата Squid.
func ParseSquid(line string, host string) (model.Event, bool) {
	m := squidRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return model.Event{}, false
	}
	sec, _ := strconv.ParseFloat(m[1], 64)
	code, _ := strconv.Atoi(m[5])
	size, _ := strconv.ParseUint(m[6], 10, 64)
	e := model.Event{
		TS:     model.FormatTS(time.Unix(int64(sec), int64((sec-float64(int64(sec)))*1e9)).UTC()),
		Source: "ngfw.squid", SourceClass: "ngfw", Vendor: "Squid", Product: "squid",
		SrcIP: m[3], Object: m[8], Node: host, Bytes: size, Raw: line,
		Attrs: map[string]string{"result": m[4], "status": m[5], "method": m[7], "hier": m[10], "mime": m[11], "elapsed_ms": m[2]},
	}
	user := m[9]
	if user != "-" {
		e.ActorName, e.ActorKind = user, "user"
		if strings.Contains(user, "@") {
			e.PII = 1
		}
	}
	switch {
	case strings.Contains(m[4], "DENIED") || code == 403 || code == 407:
		e.Action, e.Outcome, e.Severity = "session.deny", "deny", 4
	default:
		e.Action, e.Outcome = "session.allow", "allow"
	}
	e.Ensure()
	return e, true
}

/* ===== Harbor webhook: {type, occur_at, operator, event_data{repository, resources[]}} ===== */

type harborPayload struct {
	Type      string `json:"type"`
	OccurAt   int64  `json:"occur_at"`
	Operator  string `json:"operator"`
	EventData struct {
		Resources []struct {
			Digest       string `json:"digest"`
			Tag          string `json:"tag"`
			ResourceURL  string `json:"resource_url"`
			ScanOverview map[string]struct {
				Severity string `json:"severity"`
				Summary  struct {
					Total int `json:"total"`
				} `json:"summary"`
			} `json:"scan_overview"`
		} `json:"resources"`
		Repository struct {
			Name         string `json:"name"`
			Namespace    string `json:"namespace"`
			RepoFullName string `json:"repo_full_name"`
			RepoType     string `json:"repo_type"`
		} `json:"repository"`
	} `json:"event_data"`
}

func ParseHarbor(body []byte) (model.Event, error) {
	var p harborPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Type == "" {
		return model.Event{}, errors.New("harbor: не вебхук Harbor")
	}
	e := model.Event{
		Source: "harbor.audit", SourceClass: "cicd", Vendor: "Harbor", Product: "harbor",
		Action: "harbor." + strings.ToLower(p.Type), Outcome: "success", Severity: 2,
		ActorName: p.Operator, Object: p.EventData.Repository.RepoFullName, Raw: string(body),
		Attrs: map[string]string{"namespace": p.EventData.Repository.Namespace, "repo_type": p.EventData.Repository.RepoType},
	}
	if p.OccurAt > 0 {
		e.TS = model.FormatTS(time.Unix(p.OccurAt, 0).UTC())
	}
	if len(p.EventData.Resources) > 0 {
		r := p.EventData.Resources[0]
		e.Attrs["tag"], e.Attrs["digest"], e.Attrs["resource_url"] = r.Tag, r.Digest, r.ResourceURL
		for _, so := range r.ScanOverview {
			e.Attrs["scan_severity"] = so.Severity
			e.Attrs["scan_total"] = strconv.Itoa(so.Summary.Total)
			if strings.EqualFold(so.Severity, "Critical") {
				e.Severity = 7
			}
		}
	}
	switch strings.ToUpper(p.Type) {
	case "DELETE_ARTIFACT", "DELETE_CHART":
		e.Severity = 5
	case "SCANNING_FAILED", "PULL_ARTIFACT_FAILED":
		e.Outcome = "failure"
	case "QUOTA_EXCEED":
		e.Severity = 4
	}
	e.ActorKind = "user"
	if strings.HasPrefix(e.ActorName, "robot$") || e.ActorName == "" {
		e.ActorKind = "service"
	}
	e.Ensure()
	return e, nil
}

/* ===== Argo CD: notifications webhook или k8s Event-подобный JSON =====
   {"app": {...}, "action": "sync"|"OnSyncFailed"..., "user": ..., "revision": ..., "status": ...} */

type argoPayload struct {
	App struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Project string `json:"project"`
			Source  struct {
				RepoURL string `json:"repoURL"`
				Path    string `json:"path"`
			} `json:"source"`
		} `json:"spec"`
		Status struct {
			Sync struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			} `json:"sync"`
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
		} `json:"status"`
	} `json:"app"`
	Action    string `json:"action"`
	User      string `json:"user"`
	Revision  string `json:"revision"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

func ParseArgoCD(body []byte) (model.Event, error) {
	var p argoPayload
	if err := json.Unmarshal(body, &p); err != nil || p.App.Metadata.Name == "" {
		return model.Event{}, errors.New("argocd: не уведомление Argo CD")
	}
	action := strings.ToLower(strings.TrimPrefix(p.Action, "On"))
	if action == "" {
		action = strings.ToLower(p.App.Status.Sync.Status)
	}
	e := model.Event{
		Source: "argocd.audit", SourceClass: "cicd", Vendor: "Argo", Product: "argocd",
		Action: "argocd." + action, ActorName: p.User, Object: p.App.Spec.Project + "/" + p.App.Metadata.Name,
		Node: p.App.Metadata.Namespace, Severity: 2, Raw: string(body),
		Attrs: map[string]string{"repo": p.App.Spec.Source.RepoURL, "path": p.App.Spec.Source.Path,
			"revision": firstNonEmpty(p.Revision, p.App.Status.Sync.Revision), "sync": p.App.Status.Sync.Status,
			"health": p.App.Status.Health.Status, "message": p.Message},
	}
	if t, err := time.Parse(time.RFC3339, p.Timestamp); err == nil {
		e.TS = model.FormatTS(t)
	}
	switch {
	case strings.Contains(action, "fail") || strings.EqualFold(p.App.Status.Health.Status, "Degraded"):
		e.Outcome, e.Severity = "failure", 5
	case strings.Contains(action, "sync") || strings.Contains(action, "deploy"):
		e.Outcome = "success"
	default:
		e.Outcome = "unknown"
	}
	e.ActorKind = "user"
	if e.ActorName == "" || strings.HasSuffix(e.ActorName, "-controller") {
		e.ActorKind, e.ActorName = "service", firstNonEmpty(e.ActorName, "argocd-controller")
	}
	e.Ensure()
	return e, nil
}

/* ===== Jenkins Audit Trail plugin (syslog / файл):
   "Feb 05, 2026 10:12:18 AM job/deploy/ #42 Started by user i.petrov" ===== */

var jenkinsRe = regexp.MustCompile(`^(?:(\w{3} \d{1,2}, \d{4} \d{1,2}:\d{2}:\d{2} [AP]M)\s+)?(\S+)\s+(.*?)(?:\s+by\s+(?:user\s+)?(\S+))?$`)

func ParseJenkins(line, host string) (model.Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, "job/") && !strings.Contains(line, "/configure") && !strings.Contains(line, "/build") &&
		!strings.Contains(line, "/delete") && !strings.Contains(line, "credentials") {
		return model.Event{}, false
	}
	m := jenkinsRe.FindStringSubmatch(line)
	if m == nil {
		return model.Event{}, false
	}
	e := model.Event{
		Source: "jenkins.audit", SourceClass: "cicd", Vendor: "Jenkins", Product: "jenkins",
		Object: m[2], Node: host, Raw: line, Outcome: "success", Severity: 2,
		Attrs: map[string]string{"message": m[3]},
	}
	if m[1] != "" {
		if t, err := time.Parse("Jan 2, 2006 3:04:05 PM", m[1]); err == nil {
			e.TS = model.FormatTS(t)
		}
	}
	e.ActorName = strings.TrimSuffix(m[4], ",")
	if e.ActorName != "" {
		e.ActorKind = "user"
	}
	msg := strings.ToLower(m[3] + " " + m[2])
	switch {
	case strings.Contains(msg, "credentials"):
		e.Action, e.Severity = "jenkins.credentials", 6
	case strings.Contains(msg, "/configure") || strings.Contains(msg, "configsubmit"):
		e.Action, e.Severity = "jenkins.configure", 5
	case strings.Contains(msg, "/delete"):
		e.Action, e.Severity = "jenkins.delete", 5
	case strings.Contains(msg, "started"):
		e.Action = "jenkins.build.start"
	default:
		e.Action = "jenkins.event"
	}
	e.Ensure()
	return e, true
}

func init() {
	_ = fmt.Sprint // reserved
}
