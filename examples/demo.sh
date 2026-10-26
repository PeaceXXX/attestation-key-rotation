#!/bin/sh
# CLI walkthrough: init -> sign -> rotate -> old signature still
# verifies (grace) -> revoke the old key -> it stops verifying.
set -eu
cd "$(dirname "$0")/.."
go build -o /tmp/keyrot ./cmd/keyrot
STORE=/tmp/keyrot-demo.json
rm -f "$STORE"
/tmp/keyrot --store "$STORE" init
/tmp/keyrot --store "$STORE" list
OUT=$(/tmp/keyrot --store "$STORE" sign --message "attested payload")
echo "$OUT"
SIG=$(echo "$OUT" | sed 's/.*signature_b64=//')
/tmp/keyrot --store "$STORE" rotate --reason platform-migration
/tmp/keyrot --store "$STORE" list
echo "--- verify old signature during grace (expect true):"
/tmp/keyrot --store "$STORE" verify --message "attested payload" --signature "$SIG"
OLD_KID=$(/tmp/keyrot --store "$STORE" list | awk '$2=="retiring" {print $1}')
/tmp/keyrot --store "$STORE" revoke --kid "$OLD_KID"
echo "--- verify after revoke (expect false):"
/tmp/keyrot --store "$STORE" verify --message "attested payload" --signature "$SIG"
/tmp/keyrot --store "$STORE" audit-verify
