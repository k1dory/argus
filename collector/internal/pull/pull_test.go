package pull

import (
	"net/http"
	"strings"
	"testing"
)

func TestFalconDetection(t *testing.T) {
	e, err := ParseFalconEvent([]byte(`{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000,"offset":42},"event":{"ComputerName":"WKS-2214","UserName":"a.sidorov","FileName":"procdump64.exe","FilePath":"\\Device\\HarddiskVolume3\\Users\\a\\AppData\\Local\\Temp\\pd","DetectName":"Credential Dumping","DetectDescription":"LSASS memory read","SeverityName":"High","Tactic":"Credential Access","Technique":"OS Credential Dumping","LocalIP":"10.20.9.14"}}`))
	if err != nil || e.Action != "threat.detect" || e.Severity != 8 || e.Node != "WKS-2214" || !strings.Contains(e.Attrs["name"], "LSASS") {
		t.Fatalf("%v %+v", err, e)
	}
	if e.TS != "2025-09-05 09:55:38.000" {
		t.Fatalf("ts: %s", e.TS)
	}
	audit, err := ParseFalconEvent([]byte(`{"metadata":{"eventType":"AuthActivityAuditEvent","eventCreationTime":1757066138000},"event":{"UserId":"admin@corp.local","UserIp":"203.0.113.9","OperationName":"userAuthenticate","Success":false}}`))
	if err != nil || audit.Action != "falcon.userauthenticate" || audit.Outcome != "failure" || audit.SrcIP != "203.0.113.9" {
		t.Fatalf("%v %+v", err, audit)
	}
}

func TestYandexAuditIAM(t *testing.T) {
	e, err := ParseYandexAudit([]byte(`{"event_id":"e1","event_source":"resourcemanager","event_type":"yandex.cloud.audit.resourcemanager.UpdateFolderAccessBindings","event_time":"2026-09-05T04:38:07.120Z","event_status":"DONE","authentication":{"subject_type":"FEDERATED_USER_ACCOUNT","subject_name":"i.petrov@corp.local","subject_id":"aje1"},"authorization":{"authorized":true},"resource_metadata":{"path":[{"resource_type":"organization-manager.organization","resource_id":"o1","resource_name":"corp"},{"resource_type":"resource-manager.folder","resource_id":"f1","resource_name":"prod"}]},"request_metadata":{"remote_address":"10.0.5.5","user_agent":"yc"}}`))
	if err != nil || e.Action != "yc.resourcemanager.updatefolderaccessbindings" || e.Attrs["iam_change"] != "true" || e.Severity < 6 || e.ActorKind != "user" {
		t.Fatalf("%v %+v", err, e)
	}
	if !strings.HasSuffix(e.Object, "resource-manager.folder/prod") {
		t.Fatalf("object: %s", e.Object)
	}
}

func TestSigV4Deterministic(t *testing.T) {
	s := NewS3(S3Config{Endpoint: "https://storage.yandexcloud.net", Region: "ru-central1", Bucket: "audit", AccessKey: "AK", SecretKey: "SK"}, nil)
	req, _ := http.NewRequest(http.MethodGet, "https://storage.yandexcloud.net/audit?list-type=2&prefix=trails%2F", nil)
	s.sign(req, hexSHA(""))
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AK/") || !strings.Contains(auth, "/ru-central1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=") {
		t.Fatalf("authorization: %s", auth)
	}
	if req.Header.Get("x-amz-date") == "" || len(strings.Split(auth, "Signature=")[1]) != 64 {
		t.Fatalf("подпись должна быть hex sha256: %s", auth)
	}
}
