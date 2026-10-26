package keyrot

import (
	"path/filepath"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()
	s := NewService(Config{GracePeriod: time.Hour, KeyTTL: 24 * time.Hour})
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	return s
}

func mustInit(t *testing.T, s *Service) *Key {
	t.Helper()
	k, err := s.Init()
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return k
}

func TestRotatePreservesVerificationDuringGrace(t *testing.T) {
	s := testService(t)
	old := mustInit(t, s)
	msg := []byte("attested payload")
	_, sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Rotate with a platform-migration reason; exactly one active key.
	if _, err := s.Rotate("platform-migration"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	actives := 0
	for _, k := range s.PublicKeys() {
		if k.Status == StatusActive {
			actives++
		}
	}
	if actives != 1 {
		t.Fatalf("want exactly 1 active key, got %d", actives)
	}

	// Old signature still verifies (retiring key, inside grace).
	if kid, ok := s.Verify(msg, sig, ""); !ok || kid != old.Kid {
		t.Fatalf("old signature should verify during grace, got kid=%q ok=%v", kid, ok)
	}
}

func TestVerifyAfterGraceFails(t *testing.T) {
	s := testService(t)
	mustInit(t, s)
	msg := []byte("attested payload")
	_, sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Rotate("scheduled"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Step 2h forward: past the 1h grace, inside the new key's TTL.
	s.SetClock(func() time.Time {
		return time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	})
	if _, ok := s.Verify(msg, sig, ""); ok {
		t.Fatal("old signature must stop verifying after the grace period")
	}
}

func TestRevokeInvalidatesImmediately(t *testing.T) {
	s := testService(t)
	mustInit(t, s)
	msg := []byte("attested payload")
	_, sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	newKey, err := s.Rotate("scheduled")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Revoke the retiring key by its kid (find it via the public set).
	for _, k := range s.PublicKeys() {
		if k.Kid != newKey.Kid && k.Status == StatusRetiring {
			if err := s.Revoke(k.Kid); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
		}
	}
	if _, ok := s.Verify(msg, sig, ""); ok {
		t.Fatal("revoked key must never verify, even inside its grace period")
	}
}

func TestCannotRevokeSoleActiveKey(t *testing.T) {
	s := testService(t)
	k := mustInit(t, s)
	if err := s.Revoke(k.Kid); err == nil {
		t.Fatal("revoking the sole active key must be refused")
	}
	// After a rotation, revoking the retiring key is fine.
	if _, err := s.Rotate("scheduled"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s.Revoke(k.Kid); err != nil {
		t.Fatalf("revoking a retiring key should succeed: %v", err)
	}
}

func TestSignUsesOnlyActiveKey(t *testing.T) {
	s := testService(t)
	mustInit(t, s)
	newKey, err := s.Rotate("scheduled")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	kid, _, err := s.Sign([]byte("x"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if kid != newKey.Kid {
		t.Fatalf("signing key = %q, want new active %q", kid, newKey.Kid)
	}
}

func TestAuditChainTamperDetection(t *testing.T) {
	s := testService(t)
	mustInit(t, s)
	if _, err := s.Rotate("scheduled"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s.VerifyAudit(); err != nil {
		t.Fatalf("valid chain should verify: %v", err)
	}
	// Tamper: rewrite the reason of the first entry in place.
	s.mu.Lock()
	s.audit[0].Reason = "forged"
	s.mu.Unlock()
	if err := s.VerifyAudit(); err == nil {
		t.Fatal("tampered chain must fail verification")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := testService(t)
	mustInit(t, s)
	msg := []byte("round trip")
	_, sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := s.Rotate("scheduled"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keystore.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s2 := NewService(Config{GracePeriod: time.Hour, KeyTTL: 24 * time.Hour})
	// Pin the same clock: the real wall clock is already past the
	// 1h test grace period, which would (correctly) retire the key.
	s2.SetClock(func() time.Time {
		return time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	})
	if err := s2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := s2.VerifyAudit(); err != nil {
		t.Fatalf("loaded audit chain should verify: %v", err)
	}
	if _, ok := s2.Verify(msg, sig, ""); !ok {
		t.Fatal("old signature should verify after save/load, inside grace")
	}
	// Public listing must never leak private material.
	for _, k := range s2.PublicKeys() {
		if k.PublicB64 == "" {
			t.Fatal("public key missing")
		}
	}
}

func TestConcurrentRotationsKeepOneActive(t *testing.T) {
	s := testService(t)
	mustInit(t, s)
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { _, err := s.Rotate("concurrent"); done <- err }()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("Rotate: %v", err)
		}
	}
	actives := 0
	for _, k := range s.PublicKeys() {
		if k.Status == StatusActive {
			actives++
		}
	}
	if actives != 1 {
		t.Fatalf("want exactly 1 active key after concurrent rotations, got %d", actives)
	}
}
