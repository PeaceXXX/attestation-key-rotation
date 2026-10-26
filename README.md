# attestation-key-rotation

A versioned signing-key rotation service in Go (stdlib only) for
attestation-adjacent workloads: one active key, a retiring key that
keeps verifying through a grace period, revoked keys that never verify
again, and a hash-chained audit log of every lifecycle change.

## Why this exists

Attestation answers "is this workload what it claims to be?" — but
every real deployment eventually faces the next question: **what
happens when the key changes?** Platforms migrate (SGX → TDX),
keys age out, a key is suspected compromised. If rotation is an
afterthought, one of two things breaks: either old signatures stop
verifying the instant you rotate (in-flight work fails), or old keys
keep verifying forever (a compromised key never dies).

This demo implements the boring, correct middle: rotate first, keep
the old key verifiable for a bounded grace period, then retire it;
revoke immediately when you must; and keep a tamper-evident audit
trail so you can later prove which key was active, when, and why.

The trigger for building it now is a live one in the confidential
computing sphere: Intel is phasing SGX out after Diamond Rapids and
consolidating on TDX, which turns "which TEE platform are we on?" into
a lifecycle decision — and every platform migration is, underneath,
a key-rotation event. A migration that cannot rotate keys cleanly
cannot migrate at all.

> **Clean-room statement.** All concepts here are public and general
> engineering: Ed25519 signatures, key-version lifecycle, and
> hash-chained audit logs. No Intel-internal code, APIs, or
> non-public details are used or implied, and no real attestation
> evidence is processed. Keys in the demo store are throwaway demo
> keys, generated locally.

## Architecture

```
                    +---------------------------+
                    | operator / verifier       |
                    |  CLI (keyrot)  HTTP API   |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    | internal/keyrot.Service   |
                    |  lifecycle state machine  |
                    |   active -> retiring      |
                    |   retiring -> retired     |
                    |   any -> revoked (final)  |
                    +------+--------------+---+
                           |              |
              +------------v---+  +-------v----------+
              | Ed25519 keys   |  | hash-chained     |
              |  kid, status,  |  | audit log:       |
              |  grace-until,  |  |  index, action,  |
              |  expires-at    |  |  kid, prev-hash, |
              +------------+---+  |  hash            |
                           |      +-------+----------+
                    +------v--------------v------+
                    | data/keystore.json (0600) |
                    |  keys + audit, gitignored |
                    +-----------------------------+

  Sign:    active key only            -> (kid, signature)
  Verify:  active + in-grace retiring -> true / false
           retired, revoked, expired  -> always false
  Rotate:  active -> retiring (grace), fresh key -> active
  Revoke:  immediate; sole active key cannot be revoked
           (rotate first so a successor exists)
```

## Quickstart

Prerequisites: Go 1.24+.

```sh
git clone https://github.com/PeaceXXX/attestation-key-rotation.git
cd attestation-key-rotation
go build -o keyrot ./cmd/keyrot

# 1. Initialise a store (creates the first active key).
./keyrot init
# active key: k-<id> (expires <90 days out>)

# 2. Sign something with the active key.
./keyrot sign --message "attested payload"
# kid=k-<id> signature_b64=<...>

# 3. Rotate, e.g. for a platform migration. The old key becomes
#    "retiring" and keeps verifying for the grace period (72h default).
./keyrot rotate --reason platform-migration
./keyrot list
# k-<old>  retiring  grace-until <now+72h>  reason "initial"
# k-<new>  active    grace-until -           reason "platform-migration"

# 4. The old signature still verifies during grace...
./keyrot verify --message "attested payload" --signature <b64>
# verified: true (kid k-<old>)

# 5. ...until you revoke the old key, after which it never verifies.
./keyrot revoke --kid k-<old>
./keyrot verify --message "attested payload" --signature <b64>
# verified: false

# 6. Prove the audit trail is intact.
./keyrot audit          # init / retire / rotate / revoke entries
./keyrot audit-verify   # audit chain: valid
```

All of the above was run live during development (CLI walkthrough in
`examples/demo.sh`, plus an HTTP smoke test); the expected outputs
above match real runs, with key ids abbreviated.

### HTTP API

```sh
./keyrot serve --addr :8080
curl -s localhost:8080/health          # {"status":"ok"}
curl -s localhost:8080/keys            # public key set, no private keys
```

| Method & path           | Body / effect |
|-------------------------|---------------|
| `GET /health`           | Liveness check. |
| `GET /keys`             | Public key set (kid, public key, status, grace, expiry). |
| `GET /keys/{kid}`       | One public key, or 404. |
| `POST /keys/rotate`     | `{"reason": "..."}` → new active key + updated set. |
| `POST /keys/{kid}/revoke` | Revokes the key; 400 for unknown keys or the sole active key. |
| `POST /sign`            | `{"message": "..."}` → `{"kid", "signature_b64"}`. |
| `POST /verify`          | `{"message", "signature_b64", "kid?"}` → `{"verified", "kid"}`. |
| `GET /audit`            | Audit entries + `chain_valid` flag. |

### Docker

```sh
docker build -t attestation-key-rotation .
docker run -p 8080:8080 attestation-key-rotation
```

## What this demonstrates

Interview talking points, in the order I would use them:

1. **Rotation is a lifecycle, not an event.** Active → retiring →
   retired, with revocation as a separate, immediate, terminal
   transition. Each state has exactly one verification rule.
2. **Grace periods exist for in-flight work.** Verifiers cache public
   keys and requests are already signed; cutting the old key off
   instantly turns a rotation into an outage.
3. **Refusing an unsafe operation is a feature.** The service will
   not revoke the sole active key, because that leaves nothing able
   to sign — the operator must rotate first.
4. **Auditability is part of the design, not a log line.** The
   hash-chained log makes "which key signed this, and was it valid
   then?" answerable after the fact, and makes tampering detectable.
5. **Concurrency is handled at the state machine, not hoped for.**
   One mutex guards the service, so concurrent rotations can never
   produce two active keys (covered by a test).

## Limitations / how I'd productionize it

- **Single-node JSON store.** Fine for a demo; production wants a
  replicated store with transactions, and private keys in an HSM/KMS
  rather than a file — the file here is 0600 and gitignored, but it
  is still a file with private keys in it.
- **No authentication on the HTTP API.** Rotation and revocation are
  operator actions; in production they sit behind mTLS / an admin
  identity, and signing sits behind the workload's own identity.
- **Ed25519 only, no algorithm agility.** A real service versions
  algorithms alongside keys and negotiates them in the public key set.
- **No key backup / recovery story.** Losing the store loses the
  ability to prove old signatures; production needs encrypted,
  access-controlled backups and a tested restore path.
- **Clock dependence.** Grace and expiry are wall-clock decisions;
  production deployments need clock-skew bounds and monotonic
  safety margins (e.g. never retire a key before its grace *plus*
  maximum expected skew).
- **This is not an attestation verifier.** It demonstrates the key
  lifecycle that surrounds attestation; it does not verify TDX/SGX
  quotes, check TCB levels, or validate certificate chains. Those
  are companion demos (see also `tdx-tcb-gate`,
  `attestation-policy-gateway`).

## Tests

```sh
go test ./...   # key lifecycle, grace expiry, revocation, audit
                # tampering, save/load round-trip, concurrent rotation,
                # and the HTTP rotate/sign/verify flow
go vet ./...
```
