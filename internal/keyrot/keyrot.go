// Package keyrot implements versioned signing-key rotation for
// attestation-adjacent workloads: one active key, a retiring key that
// stays verifiable through a grace period, revoked/retired keys that
// never verify again, and a hash-chained audit log of every change.
//
// The crypto here is deliberately ordinary (Ed25519, SHA-256). The
// interesting part is the lifecycle policy, which is exactly the part
// that breaks in production: a verifier must accept signatures made
// just before a rotation, must stop accepting them after the grace
// period, and must be able to prove later which key was active when.
package keyrot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Status is the lifecycle state of a single key version.
type Status string

const (
	StatusActive   Status = "active"
	StatusRetiring Status = "retiring"
	StatusRetired  Status = "retired"
	StatusRevoked  Status = "revoked"
)

// Config tunes the lifecycle policy. GracePeriod is how long a
// retiring key keeps verifying after its successor activates; KeyTTL
// is the maximum lifetime of a key version.
type Config struct {
	GracePeriod time.Duration
	KeyTTL      time.Duration
}

// DefaultConfig is a production-shaped default: 72h of overlap so
// in-flight verifiers and cached public keys drain naturally, and a
// 90-day maximum key lifetime.
func DefaultConfig() Config {
	return Config{GracePeriod: 72 * time.Hour, KeyTTL: 90 * 24 * time.Hour}
}

// Key is one key version. PrivateB64 is present only in the local
// store file; it is stripped from every public listing.
type Key struct {
	Kid        string     `json:"kid"`
	PublicB64  string     `json:"public_key_b64"`
	PrivateB64 string     `json:"private_key_b64,omitempty"`
	Status     Status     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Reason     string     `json:"reason"`
}

// PublicKey is the verifier-facing view of a key: no private material.
type PublicKey struct {
	Kid        string     `json:"kid"`
	PublicB64  string     `json:"public_key_b64"`
	Status     Status     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Reason     string     `json:"reason"`
}

// AuditEntry is one hash-chained log record. Hash covers every other
// field plus PrevHash, so editing or deleting any earlier entry
// invalidates every entry after it.
type AuditEntry struct {
	Index     int       `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Kid       string    `json:"kid"`
	Reason    string    `json:"reason"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

func hashEntry(index int, ts time.Time, action, kid, reason, prev string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		index, ts.Format(time.RFC3339Nano), action, kid, reason, prev)))
	return hex.EncodeToString(sum[:])
}

// Service is the rotation state machine. All methods are safe for
// concurrent use; Rotate is the only writer that creates keys, so two
// racing rotations can never produce two active keys.
type Service struct {
	mu    sync.Mutex
	cfg   Config
	keys  []*Key
	audit []AuditEntry
	now   func() time.Time
}

// NewService returns an empty service. Call Init (or load a store)
// before signing.
func NewService(cfg Config) *Service {
	return &Service{cfg: cfg, now: time.Now}
}

// SetClock overrides the clock; tests use it to step past grace and TTL.
func (s *Service) SetClock(f func() time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.now = f }

func (s *Service) at() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// refreshLocked advances time-driven transitions: a retiring key
// whose grace expired becomes retired, and any non-revoked key past
// its TTL becomes retired. Revoked is terminal and never changes.
func (s *Service) refreshLocked() {
	now := s.at()
	for _, k := range s.keys {
		switch k.Status {
		case StatusRetiring:
			if k.GraceUntil != nil && !now.Before(*k.GraceUntil) {
				k.Status = StatusRetired
				k.GraceUntil = nil
			}
		case StatusActive:
			if !now.Before(k.ExpiresAt) {
				k.Status = StatusRetired
			}
		}
	}
}

func (s *Service) newKeyLocked(reason string) (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var kid string
	for {
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		kid = "k-" + hex.EncodeToString(b)
		if s.findLocked(kid) == nil {
			break
		}
	}
	now := s.at()
	k := &Key{
		Kid:        kid,
		PublicB64:  base64.StdEncoding.EncodeToString(pub),
		PrivateB64: base64.StdEncoding.EncodeToString(priv),
		Status:     StatusActive,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.KeyTTL),
		Reason:     reason,
	}
	return k, nil
}

func (s *Service) findLocked(kid string) *Key {
	for _, k := range s.keys {
		if k.Kid == kid {
			return k
		}
	}
	return nil
}

func (s *Service) appendAuditLocked(action, kid, reason string) {
	prev := "GENESIS"
	if n := len(s.audit); n > 0 {
		prev = s.audit[n-1].Hash
	}
	e := AuditEntry{
		Index:     len(s.audit),
		Timestamp: s.at(),
		Action:    action,
		Kid:       kid,
		Reason:    reason,
		PrevHash:  prev,
	}
	e.Hash = hashEntry(e.Index, e.Timestamp, e.Action, e.Kid, e.Reason, e.PrevHash)
	s.audit = append(s.audit, e)
}

// Init creates the first key when the store is empty. It is a no-op
// (returning the existing active key) when keys already exist.
func (s *Service) Init() (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	for _, k := range s.keys {
		if k.Status == StatusActive {
			return k, nil
		}
	}
	if len(s.keys) > 0 {
		return nil, errors.New("no active key exists; rotate to create one")
	}
	k, err := s.newKeyLocked("initial")
	if err != nil {
		return nil, err
	}
	s.keys = append(s.keys, k)
	s.appendAuditLocked("init", k.Kid, "initial")
	return k, nil
}

// Rotate demotes the current active key to retiring (verifiable until
// now+grace) and activates a fresh key. The old key's signatures keep
// verifying through the grace period, so in-flight work is not broken
// by the rotation itself.
func (s *Service) Rotate(reason string) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	if len(s.keys) == 0 {
		return nil, errors.New("no keys yet; run init first")
	}
	now := s.at()
	graceUntil := now.Add(s.cfg.GracePeriod)
	for _, k := range s.keys {
		if k.Status == StatusActive {
			k.Status = StatusRetiring
			g := graceUntil
			k.GraceUntil = &g
			s.appendAuditLocked("retire", k.Kid, reason)
		}
	}
	k, err := s.newKeyLocked(reason)
	if err != nil {
		return nil, err
	}
	s.keys = append(s.keys, k)
	s.appendAuditLocked("rotate", k.Kid, reason)
	return k, nil
}

// Revoke immediately and permanently invalidates a key. Revoking the
// sole active key is refused: rotate first, so there is always a key
// able to sign. Revoking an active key when a retiring key exists
// promotes the newest retiring key back to active.
func (s *Service) Revoke(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	k := s.findLocked(kid)
	if k == nil {
		return fmt.Errorf("unknown key %q", kid)
	}
	if k.Status == StatusRevoked {
		return fmt.Errorf("key %q is already revoked", kid)
	}
	if k.Status == StatusActive {
		var successor *Key
		for _, c := range s.keys {
			if c.Status == StatusRetiring && (successor == nil || c.CreatedAt.After(successor.CreatedAt)) {
				successor = c
			}
		}
		if successor == nil {
			return errors.New("cannot revoke the sole active key: rotate first so a successor exists")
		}
		successor.Status = StatusActive
		successor.GraceUntil = nil
		s.appendAuditLocked("promote", successor.Kid, "revocation of active key")
	}
	k.Status = StatusRevoked
	k.GraceUntil = nil
	s.appendAuditLocked("revoke", k.Kid, "")
	return nil
}

// Sign signs with the active key only. There is exactly one active
// key at any time, so a signature is unambiguous about its version.
func (s *Service) Sign(message []byte) (kid string, sig []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	for _, k := range s.keys {
		if k.Status == StatusActive {
			priv, derr := base64.StdEncoding.DecodeString(k.PrivateB64)
			if derr != nil {
				return "", nil, derr
			}
			return k.Kid, ed25519.Sign(ed25519.PrivateKey(priv), message), nil
		}
	}
	return "", nil, errors.New("no active key to sign with")
}

// Verify reports whether sig is a valid signature over message. With
// kid empty it tries every verifiable key; with kid set it tries only
// that key. Active and in-grace retiring keys verify; retired,
// revoked, and expired keys never do.
func (s *Service) Verify(message, sig []byte, kid string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	now := s.at()
	for _, k := range s.keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		switch k.Status {
		case StatusActive:
			// verifiable until expiry (refresh already retired it past TTL)
		case StatusRetiring:
			if k.GraceUntil == nil || !now.Before(*k.GraceUntil) {
				continue
			}
		default:
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicB64)
		if err != nil {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(pub), message, sig) {
			return k.Kid, true
		}
	}
	return "", false
}

// PublicKeys returns the verifier-facing key set (JWKS-style shape:
// kid + public key + status), with no private material.
func (s *Service) PublicKeys() []PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	out := make([]PublicKey, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, PublicKey{
			Kid: k.Kid, PublicB64: k.PublicB64, Status: k.Status,
			CreatedAt: k.CreatedAt, GraceUntil: k.GraceUntil,
			ExpiresAt: k.ExpiresAt, Reason: k.Reason,
		})
	}
	return out
}

// Audit returns a copy of the audit log.
func (s *Service) Audit() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEntry, len(s.audit))
	copy(out, s.audit)
	return out
}

// VerifyAudit recomputes the whole hash chain. Any edit, deletion,
// or reordering of an earlier entry fails verification.
func (s *Service) VerifyAudit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := "GENESIS"
	for i, e := range s.audit {
		if e.Index != i {
			return fmt.Errorf("audit entry %d has wrong index %d", i, e.Index)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit entry %d breaks the chain", i)
		}
		if e.Hash != hashEntry(e.Index, e.Timestamp, e.Action, e.Kid, e.Reason, e.PrevHash) {
			return fmt.Errorf("audit entry %d has been tampered with", i)
		}
		prev = e.Hash
	}
	return nil
}

// state is the on-disk shape of a Service.
type state struct {
	Keys  []*Key       `json:"keys"`
	Audit []AuditEntry `json:"audit"`
}

// Save persists keys (including private material) and the audit log.
// The file is created 0600: it is a demo keystore, not a secret to
// share, and it is gitignored for exactly that reason.
func (s *Service) Save(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := state{Keys: s.keys, Audit: s.audit}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Load restores a store written by Save. Config and clock are kept.
func (s *Service) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = st.Keys
	s.audit = st.Audit
	return nil
}

// Config returns the service's lifecycle policy.
func (s *Service) Config() Config { return s.cfg }
