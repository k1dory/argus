package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Ротация и отзыв токена GitLab (audit event streaming): secret_id — имя
// токена, token_id — его id, project — путь проекта. Это ключ close_match
// правила ci-secret-echo вместе с object.
func TestGitLabTokenRotationSecretAttrs(t *testing.T) {
	for _, tc := range []struct{ name, body, action string }{
		{"rotated, поля на корне", `{"id":7,"author_name":"i.petrov","entity_path":"sec/argus","entity_type":"Project","event_type":"project_access_token_rotated","target_id":4711,"target_type":"PersonalAccessToken","target_details":"REGISTRY_TOKEN","created_at":"2026-09-05T05:00:00Z","details":{"author_name":"i.petrov","custom_message":"Rotated project access token"}}`, "gitlab.project_access_token_rotated"},
		{"revoked, поля в details", `{"id":8,"author_name":"i.petrov","entity_path":"sec/argus","entity_type":"Project","event_type":"project_access_token_revoked","created_at":"2026-09-05T05:00:00Z","details":{"author_name":"i.petrov","target_id":4711,"target_type":"PersonalAccessToken","target_details":"REGISTRY_TOKEN"}}`, "gitlab.project_access_token_revoked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := ParseGitLab([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if e.Action != tc.action || e.Object != "sec/argus" {
				t.Fatalf("action=%q object=%q", e.Action, e.Object)
			}
			for k, want := range map[string]string{"secret_id": "REGISTRY_TOKEN", "token_id": "4711", "token_name": "REGISTRY_TOKEN", "project": "sec/argus", "target_type": "PersonalAccessToken"} {
				if e.Attrs[k] != want {
					t.Errorf("attrs.%s = %q, want %q", k, e.Attrs[k], want)
				}
			}
		})
	}
}

func TestGitLabOtherAuditHasNoSecretAttrs(t *testing.T) {
	e, err := ParseGitLab([]byte(`{"id":1,"author_name":"i.petrov","entity_path":"sec/argus-rules","entity_type":"Project","event_type":"project_access_token_created","target_id":5,"target_details":"NEW_TOKEN","created_at":"2026-09-05T04:01:38Z","details":{"author_name":"i.petrov"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Attrs["secret_id"] != "" {
		t.Fatalf("создание токена — не ротация: %v", e.Attrs)
	}
	// id и имя созданного токена — сведения для разбора; автозакрытие на них
	// не опирается (S3: закрывает только отзыв доказанно того же токена).
	if e.Attrs["token_id"] != "5" || e.Attrs["token_name"] != "NEW_TOKEN" {
		t.Fatalf("создание токена: token_id/token_name: %v", e.Attrs)
	}
}

// Токен без имени — ключом становится id.
func TestRotationWithoutNameFallsBackToID(t *testing.T) {
	e, err := ParseGitLab([]byte(`{"id":9,"author_name":"i.petrov","entity_path":"sec/argus","entity_type":"Project","event_type":"group_access_token_revoked","target_id":42,"created_at":"2026-09-05T05:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Attrs["secret_id"] != "42" {
		t.Fatalf("secret_id = %q", e.Attrs["secret_id"])
	}
}

func ciLog(log string) model.Event {
	e := model.Event{SourceClass: "cicd", Source: "gitlab.ci", Action: "gitlab.build.success", Object: "sec/argus", Attrs: map[string]string{"log": log}}
	SecretAttrs(&e)
	return e
}

// Утечка: имя переменной из лога — тот же secret_id, что у ротации токена.
func TestLeakSecretIDFromLog(t *testing.T) {
	e := ciLog("+ docker login -u robot$ci -p REGISTRY_TOKEN=glrt-9f8a7b6c5d4e3f2a1b0c harbor.corp.local")
	if e.Attrs["secret_id"] != "REGISTRY_TOKEN" || e.Attrs["project"] != "sec/argus" {
		t.Fatalf("attrs %v", e.Attrs)
	}
	// Повтор того же имени — один секрет.
	if e := ciLog("TOKEN=aaaaaaaaaaaa; echo token=aaaaaaaaaaaa"); e.Attrs["secret_id"] != "TOKEN" {
		t.Fatalf("attrs %v", e.Attrs)
	}
}

// Два секрета в строке: один ключ их не опишет — secret_id не ставится,
// инцидент закроет только человек.
func TestTwoLeakedSecretsLeaveNoKey(t *testing.T) {
	e := ciLog("DEPLOY_TOKEN=aaaaaaaaaaaa DB_PASSWORD=bbbbbbbbbbbb")
	if e.Attrs["secret_id"] != "" || e.Attrs["secret_names"] != "DEPLOY_TOKEN,DB_PASSWORD" {
		t.Fatalf("attrs %v", e.Attrs)
	}
}

func TestSecretAttrsKeepsGivenAndSkipsOtherClasses(t *testing.T) {
	e := model.Event{SourceClass: "cicd", Action: "gitlab.build.success", Attrs: map[string]string{"log": "TOKEN=aaaaaaaaaaaa", "secret_id": "given"}}
	SecretAttrs(&e)
	if e.Attrs["secret_id"] != "given" {
		t.Fatal("заданный secret_id перезаписан")
	}
	e = model.Event{SourceClass: "edr", Attrs: map[string]string{"log": "TOKEN=aaaaaaaaaaaa"}}
	SecretAttrs(&e)
	if e.Attrs["secret_id"] != "" {
		t.Fatal("secret_id у события не CI/CD")
	}
	// Короткое значение (меньше 8 символов) правило не считает утечкой.
	if e := ciLog("TOKEN=abc"); e.Attrs["secret_id"] != "" {
		t.Fatalf("attrs %v", e.Attrs)
	}
}

// Сквозная фикстура «утечка → ротация» для движка
// (engine/internal/incidents: TestCollectorFixtureRotationClosesLeak): события
// получены этим нормализатором, а не написаны руками. ARGUS_UPDATE_FIXTURES=1
// перезаписывает файл; иначе тест сверяет, что нормализатор даёт то же.
func TestSecretRotationFixture(t *testing.T) {
	leakEv := model.Event{TS: "2026-10-12 04:01:38.000", Source: "gitlab.ci", SourceClass: "cicd", Vendor: "GitLab", Product: "gitlab",
		Action: "gitlab.build.success", Outcome: "success", Severity: 2, ActorName: "project_7_bot", ActorKind: "service", Object: "sec/argus", Node: "runner-07",
		Attrs: map[string]string{"job": "build:push", "log": "+ docker login -u robot$ci -p REGISTRY_TOKEN=glrt-9f8a7b6c5d4e3f2a1b0c harbor.corp.local"}}
	leakEv.Ensure()
	SecretAttrs(&leakEv) // путь /ingest/events
	audit := func(id int, author, event string, tokenID int, name, at string) model.Event {
		e, err := ParseGitLab([]byte(fmt.Sprintf(`{"id":%d,"author_name":%q,"entity_path":"sec/argus","entity_type":"Project","event_type":%q,"target_id":%d,"target_type":"PersonalAccessToken","target_details":%q,"created_at":%q}`, id, author, event, tokenID, name, at)))
		if err != nil {
			t.Fatal(err)
		}
		e.Raw = ""
		return e
	}
	// Настоящий REGISTRY_TOKEN (4702) создан задолго до утечки; однофамилец
	// (4799) создан Maintainer'ом после утечки и тут же отозван.
	evs := []model.Event{
		audit(1, "i.petrov", "project_access_token_created", 4702, "REGISTRY_TOKEN", "2026-09-01T10:00:00Z"),
		leakEv,
		audit(2, "i.petrov", "project_access_token_rotated", 4701, "DEPLOY_TOKEN", "2026-10-12T04:11:00Z"),
		audit(3, "m.intruder", "project_access_token_created", 4799, "REGISTRY_TOKEN", "2026-10-12T04:12:00Z"),
		audit(4, "m.intruder", "project_access_token_revoked", 4799, "REGISTRY_TOKEN", "2026-10-12T04:13:00Z"),
		audit(5, "i.petrov", "project_access_token_rotated", 4702, "REGISTRY_TOKEN", "2026-10-12T04:14:00Z"),
	}
	var b strings.Builder
	for _, e := range evs {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	path := "../../../fixtures/events/secret-rotation.ndjson"
	if os.Getenv("ARGUS_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != b.String() {
		t.Fatalf("фикстура устарела, перегенерируйте: ARGUS_UPDATE_FIXTURES=1 go test ./internal/parse/\n%s", b.String())
	}
}
