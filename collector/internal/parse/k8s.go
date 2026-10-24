package parse

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Kubernetes audit webhook: audit.k8s.io/v1 EventList или одиночный Event.
type k8sEvent struct {
	Kind       string `json:"kind"`
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	Level      string `json:"level"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	} `json:"responseStatus"`
	RequestReceived time.Time         `json:"requestReceivedTimestamp"`
	StageTimestamp  time.Time         `json:"stageTimestamp"`
	Annotations     map[string]string `json:"annotations"`
	RequestObject   json.RawMessage   `json:"requestObject"`
}

type k8sList struct {
	Kind  string     `json:"kind"`
	Items []k8sEvent `json:"items"`
}

// ParseK8sAudit принимает тело вебхука; cluster — имя кластера для поля node.
func ParseK8sAudit(body []byte, cluster string) ([]model.Event, error) {
	var list k8sList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("k8s audit: %w", err)
	}
	items := list.Items
	if list.Kind == "Event" || (len(items) == 0 && list.Kind != "EventList") {
		var single k8sEvent
		if err := json.Unmarshal(body, &single); err != nil || single.Verb == "" {
			return nil, errors.New("k8s audit: ни EventList, ни Event")
		}
		items = []k8sEvent{single}
	}
	out := make([]model.Event, 0, len(items))
	for _, it := range items {
		if it.Stage != "" && it.Stage != "ResponseComplete" && it.Stage != "Panic" {
			continue // дубли стадий RequestReceived не нужны
		}
		e := k8sToEvent(it, cluster)
		raw, _ := json.Marshal(it)
		e.Raw = string(raw)
		e.Ensure()
		out = append(out, e)
	}
	return out, nil
}

func k8sToEvent(it k8sEvent, cluster string) model.Event {
	ts := it.StageTimestamp
	if ts.IsZero() {
		ts = it.RequestReceived
	}
	e := model.Event{
		TS:          model.FormatTS(ts),
		Source:      "k8s.audit",
		SourceClass: "k8s",
		Vendor:      "Kubernetes",
		Product:     "kube-apiserver",
		Node:        cluster,
		SessionID:   it.AuditID,
		ActorName:   it.User.Username,
		Attrs: map[string]string{
			"verb":       it.Verb,
			"stage":      it.Stage,
			"user_agent": it.UserAgent,
			"uri":        it.RequestURI,
		},
	}
	if len(it.SourceIPs) > 0 {
		e.SrcIP = it.SourceIPs[0]
	}
	switch {
	case strings.HasPrefix(it.User.Username, "system:serviceaccount:"):
		e.ActorKind = "service"
	case strings.HasPrefix(it.User.Username, "system:"):
		e.ActorKind = "system"
	default:
		e.ActorKind = "user"
	}
	if it.ImpersonatedUser != nil {
		e.Attrs["impersonated"] = it.ImpersonatedUser.Username
	}
	resource := ""
	if it.ObjectRef != nil {
		resource = it.ObjectRef.Resource
		if it.ObjectRef.Subresource != "" {
			resource += "/" + it.ObjectRef.Subresource
		}
		e.Object = strings.Trim(fmt.Sprintf("%s/%s/%s", it.ObjectRef.Namespace, it.ObjectRef.Resource, it.ObjectRef.Name), "/")
		e.Attrs["namespace"] = it.ObjectRef.Namespace
		e.Attrs["resource"] = it.ObjectRef.Resource
		e.Attrs["api_group"] = it.ObjectRef.APIGroup
	}
	e.Action = "k8s." + it.Verb
	if resource != "" {
		e.Action = "k8s." + it.Verb + "." + resource
	}
	if it.ResponseStatus != nil {
		e.Attrs["code"] = fmt.Sprint(it.ResponseStatus.Code)
		switch {
		case it.ResponseStatus.Code == 401 || it.ResponseStatus.Code == 403:
			e.Outcome = "deny"
			e.Severity = 5
		case it.ResponseStatus.Code >= 200 && it.ResponseStatus.Code < 300:
			e.Outcome = "success"
		default:
			e.Outcome = "failure"
		}
	}
	if d, ok := it.Annotations["authorization.k8s.io/decision"]; ok {
		e.Attrs["decision"] = d
	}
	// Привилегированные изменения RBAC — заметнее по умолчанию.
	if it.ObjectRef != nil && it.ObjectRef.APIGroup == "rbac.authorization.k8s.io" &&
		(it.Verb == "create" || it.Verb == "update" || it.Verb == "patch") {
		e.Severity = max(e.Severity, 6)
		e.Attrs["rbac_change"] = "true"
		if strings.Contains(string(it.RequestObject), `"cluster-admin"`) {
			e.Attrs["role_ref"] = "cluster-admin"
			e.Severity = 8
		}
	}
	return e
}
