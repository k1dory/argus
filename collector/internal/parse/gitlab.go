package parse

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// GitLab: audit event streaming (Enterprise), system hooks и pipeline/job
// webhooks — три разных формы, один нормализованный результат.
type gitlabPayload struct {
	// audit event streaming
	ID            json.Number `json:"id"`
	AuthorName    string      `json:"author_name"`
	TargetID      json.Number `json:"target_id"`
	TargetType    string      `json:"target_type"`
	TargetDetails string      `json:"target_details"`
	EntityPath    string      `json:"entity_path"`
	EntityType    string      `json:"entity_type"`
	EventType     string      `json:"event_type"`
	IPAddress     string      `json:"ip_address"`
	CreatedAt     string      `json:"created_at"`
	Details       struct {
		AuthorName    string      `json:"author_name"`
		CustomMessage string      `json:"custom_message"`
		TargetID      json.Number `json:"target_id"`
		TargetDetails string      `json:"target_details"`
		TargetType    string      `json:"target_type"`
		IPAddress     string      `json:"ip_address"`
		Change        string      `json:"change"`
		From          string      `json:"from"`
		To            string      `json:"to"`
	} `json:"details"`
	// system hooks
	EventName string `json:"event_name"`
	UserName  string `json:"user_username"`
	UserEmail string `json:"user_email"`
	GroupPath string `json:"group_path"`
	// pipeline / job webhooks
	ObjectKind       string `json:"object_kind"`
	ObjectAttributes struct {
		Status string `json:"status"`
		Ref    string `json:"ref"`
		Stage  string `json:"stage"`
		Name   string `json:"name"`
		ID     int64  `json:"id"`
	} `json:"object_attributes"`
	User struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	Project struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	Runner struct {
		Description string `json:"description"`
		IsShared    bool   `json:"is_shared"`
	} `json:"runner"`
	BuildStatus string `json:"build_status"`
	BuildName   string `json:"build_name"`
	BuildStage  string `json:"build_stage"`
	Ref         string `json:"ref"`
}

func ParseGitLab(body []byte) (model.Event, error) {
	var p gitlabPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return model.Event{}, fmt.Errorf("gitlab: %w", err)
	}
	e := model.Event{
		Source:      "gitlab.audit",
		SourceClass: "cicd",
		Vendor:      "GitLab",
		Product:     "gitlab",
		Raw:         string(body),
		Attrs:       map[string]string{},
	}
	switch {
	case p.EventType != "" || p.Details.AuthorName != "":
		e.Action = "gitlab." + firstNonEmpty(p.EventType, "audit")
		e.ActorName = firstNonEmpty(p.AuthorName, p.Details.AuthorName)
		e.Object = firstNonEmpty(p.EntityPath, p.Details.TargetDetails)
		e.SrcIP = firstNonEmpty(p.IPAddress, p.Details.IPAddress)
		e.Outcome = "success"
		e.Severity = 4
		e.Attrs["entity_type"] = p.EntityType
		e.Attrs["target_type"] = firstNonEmpty(p.TargetType, p.Details.TargetType)
		if IsSecretChange(e.Action) || IsTokenCreated(e.Action) {
			// Ротация/отзыв токена: id и имя токена, проект — для close_match
			// утечки (secrets.go). Имя — target_details, у токена это его имя.
			// Создание токена — тот же id и имя: для разбора.
			e.Attrs["token_id"] = firstNonEmpty(p.TargetID.String(), p.Details.TargetID.String())
			e.Attrs["token_name"] = firstNonEmpty(p.TargetDetails, p.Details.TargetDetails)
			e.Attrs["project"] = p.EntityPath
		}
		if p.Details.CustomMessage != "" {
			e.Attrs["message"] = p.Details.CustomMessage
		}
		if p.Details.Change != "" {
			e.Attrs["change"] = fmt.Sprintf("%s: %s → %s", p.Details.Change, p.Details.From, p.Details.To)
			e.Severity = 6
		}
		if t, err := time.Parse(time.RFC3339Nano, p.CreatedAt); err == nil {
			e.TS = model.FormatTS(t)
		}
	case p.ObjectKind == "pipeline" || p.ObjectKind == "build" || p.ObjectKind == "job":
		e.Source = "gitlab.ci"
		status := firstNonEmpty(p.ObjectAttributes.Status, p.BuildStatus)
		e.Action = "gitlab." + p.ObjectKind + "." + status
		e.ActorName = firstNonEmpty(p.User.Username, p.User.Name)
		e.Object = p.Project.PathWithNamespace
		e.Attrs["ref"] = firstNonEmpty(p.ObjectAttributes.Ref, p.Ref)
		e.Attrs["stage"] = firstNonEmpty(p.ObjectAttributes.Stage, p.BuildStage)
		e.Attrs["job"] = firstNonEmpty(p.ObjectAttributes.Name, p.BuildName)
		e.Attrs["runner"] = p.Runner.Description
		if p.Runner.IsShared {
			e.Attrs["runner_shared"] = "true"
		}
		switch status {
		case "success":
			e.Outcome = "success"
		case "failed", "canceled":
			e.Outcome = "failure"
		default:
			e.Outcome = "unknown"
		}
		e.Severity = 2
	case p.EventName != "":
		e.Action = "gitlab." + p.EventName
		e.ActorName = firstNonEmpty(p.UserName, p.User.Username)
		e.Object = firstNonEmpty(p.GroupPath, p.Project.PathWithNamespace)
		e.Outcome = "success"
		e.Severity = 3
		if strings.Contains(p.EventName, "add_to_group") || strings.Contains(p.EventName, "access") {
			e.Severity = 5
		}
	default:
		return model.Event{}, errors.New("gitlab: неизвестная форма вебхука")
	}
	if e.ActorName != "" {
		e.ActorKind = "user"
		if strings.HasPrefix(e.ActorName, "project_") || strings.HasSuffix(e.ActorName, "_bot") {
			e.ActorKind = "service"
		}
	}
	if p.UserEmail != "" || p.User.Email != "" {
		e.PII = 1 // e-mail в теле — ПДн
	}
	e.Ensure()
	SecretAttrs(&e)
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
