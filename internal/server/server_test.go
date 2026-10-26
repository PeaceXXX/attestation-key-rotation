package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PeaceXXX/attestation-key-rotation/internal/keyrot"
)

func TestHTTPFlow(t *testing.T) {
	svc := keyrot.NewService(keyrot.Config{GracePeriod: time.Hour, KeyTTL: 24 * time.Hour})
	if _, err := svc.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	h := Handler(svc, func() error { return nil })

	post := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	sign := post("/sign", `{"message":"hello"}`)
	if sign.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", sign.Code, sign.Body.String())
	}
	var signed struct {
		Kid string `json:"kid"`
		Sig string `json:"signature_b64"`
	}
	if err := json.Unmarshal(sign.Body.Bytes(), &signed); err != nil {
		t.Fatalf("sign body: %v", err)
	}

	// Rotate, then the old signature must still verify (grace period).
	rot := post("/keys/rotate", `{"reason":"platform-migration"}`)
	if rot.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rot.Code, rot.Body.String())
	}
	ver := post("/verify", `{"message":"hello","signature_b64":"`+signed.Sig+`"}`)
	var out struct {
		Verified bool   `json:"verified"`
		Kid      string `json:"kid"`
	}
	if err := json.Unmarshal(ver.Body.Bytes(), &out); err != nil {
		t.Fatalf("verify body: %v", err)
	}
	if !out.Verified || out.Kid != signed.Kid {
		t.Fatalf("old signature should verify during grace: %+v", out)
	}

	// Revoking a key that does not exist is a clean 400, not a crash.
	bad := post("/keys/k-nope/revoke", `{}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("revoke unknown: want 400, got %d", bad.Code)
	}
}
