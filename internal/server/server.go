// Package server exposes a Service over HTTP: the shape a verifier
// or an operator would actually call (public key set, rotation,
// revocation, sign/verify). It is a thin layer — all lifecycle rules
// live in keyrot, so the HTTP surface cannot accidentally bypass them.
package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/PeaceXXX/attestation-key-rotation/internal/keyrot"
)

// Handler wires a Service to HTTP routes. save is called after every
// mutation so the on-disk store never lags the served state.
func Handler(svc *keyrot.Service, save func() error) http.Handler {
	mux := http.NewServeMux()

	write := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, code int, err error) {
		write(w, code, map[string]string{"error": err.Error()})
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		if err := json.NewDecoder(r.Body).Decode(v); err != nil {
			fail(w, http.StatusBadRequest, err)
			return false
		}
		return true
	}

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// GET /keys — the verifier-facing key set (no private material).
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusOK, map[string]any{"keys": svc.PublicKeys()})
	})

	mux.HandleFunc("GET /keys/{kid}", func(w http.ResponseWriter, r *http.Request) {
		for _, k := range svc.PublicKeys() {
			if k.Kid == r.PathValue("kid") {
				write(w, http.StatusOK, k)
				return
			}
		}
		write(w, http.StatusNotFound, map[string]string{"error": "unknown key"})
	})

	mux.HandleFunc("POST /keys/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength > 0 && !decode(w, r, &req) {
			return
		}
		k, err := svc.Rotate(req.Reason)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := save(); err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		write(w, http.StatusOK, map[string]any{"kid": k.Kid, "keys": svc.PublicKeys()})
	})

	mux.HandleFunc("POST /keys/{kid}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Revoke(r.PathValue("kid")); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if err := save(); err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		write(w, http.StatusOK, map[string]any{"revoked": r.PathValue("kid"), "keys": svc.PublicKeys()})
	})

	mux.HandleFunc("POST /sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Message string `json:"message"`
		}
		if !decode(w, r, &req) {
			return
		}
		kid, sig, err := svc.Sign([]byte(req.Message))
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		write(w, http.StatusOK, map[string]string{
			"kid": kid, "signature_b64": base64.StdEncoding.EncodeToString(sig),
		})
	})

	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Message      string `json:"message"`
			SignatureB64 string `json:"signature_b64"`
			Kid          string `json:"kid,omitempty"`
		}
		if !decode(w, r, &req) {
			return
		}
		sig, err := base64.StdEncoding.DecodeString(req.SignatureB64)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		kid, ok := svc.Verify([]byte(req.Message), sig, req.Kid)
		write(w, http.StatusOK, map[string]any{"verified": ok, "kid": kid})
	})

	mux.HandleFunc("GET /audit", func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusOK, map[string]any{
			"entries": svc.Audit(), "chain_valid": svc.VerifyAudit() == nil,
		})
	})

	return mux
}
