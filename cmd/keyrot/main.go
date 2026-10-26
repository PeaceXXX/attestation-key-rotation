// Command keyrot is the operator CLI for the attestation key
// rotation service: init a store, serve the HTTP API, rotate, list,
// revoke, sign, verify, and check the audit chain.
//
// Usage:
//
//	keyrot --store data/keystore.json init
//	keyrot --store data/keystore.json serve --addr :8080
//	keyrot --store data/keystore.json rotate --reason platform-migration
//	keyrot --store data/keystore.json list
//	keyrot --store data/keystore.json revoke --kid k-abcdef123456
//	keyrot --store data/keystore.json sign --message hello
//	keyrot --store data/keystore.json verify --message hello --signature <b64> [--kid k-...]
//	keyrot --store data/keystore.json audit
//	keyrot --store data/keystore.json audit-verify
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/PeaceXXX/attestation-key-rotation/internal/keyrot"
	"github.com/PeaceXXX/attestation-key-rotation/internal/server"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: keyrot [--store PATH] [--grace DUR] [--ttl DUR] <init|serve|rotate|list|revoke|sign|verify|audit|audit-verify> [flags]")
	os.Exit(2)
}

func main() {
	fs := flag.NewFlagSet("keyrot", flag.ExitOnError)
	storePath := fs.String("store", "data/keystore.json", "path to the keystore file")
	grace := fs.Duration("grace", 72*time.Hour, "grace period for retiring keys")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "maximum key lifetime")
	if len(os.Args) < 2 {
		usage()
	}
	// Split global flags from the subcommand: flags come first.
	args := os.Args[1:]
	i := 0
	for i < len(args) && len(args[i]) > 0 && args[i][0] == '-' {
		i += 2 // every global flag here takes a value
	}
	if i >= len(args) {
		usage()
	}
	if err := fs.Parse(args[:i]); err != nil {
		usage()
	}
	cmd := args[i]
	rest := args[i+1:]

	svc := keyrot.NewService(keyrot.Config{GracePeriod: *grace, KeyTTL: *ttl})
	load := func() {
		if _, err := os.Stat(*storePath); err == nil {
			if err := svc.Load(*storePath); err != nil {
				fatal(err)
			}
		}
	}
	save := func() {
		if err := os.MkdirAll(filepath.Dir(*storePath), 0755); err != nil {
			fatal(err)
		}
		if err := svc.Save(*storePath); err != nil {
			fatal(err)
		}
	}

	switch cmd {
	case "init":
		load()
		k, err := svc.Init()
		if err != nil {
			fatal(err)
		}
		save()
		fmt.Printf("active key: %s (expires %s)\n", k.Kid, k.ExpiresAt.Format(time.RFC3339))

	case "serve":
		sf := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := sf.String("addr", ":8080", "listen address")
		_ = sf.Parse(rest)
		load()
		if _, err := svc.Init(); err != nil {
			fatal(err)
		}
		save()
		fmt.Printf("listening on %s (store %s)\n", *addr, *storePath)
		if err := http.ListenAndServe(*addr, server.Handler(svc, func() error {
			save()
			return nil
		})); err != nil {
			fatal(err)
		}

	case "rotate":
		sf := flag.NewFlagSet("rotate", flag.ExitOnError)
		reason := sf.String("reason", "", "why this rotation is happening, e.g. platform-migration")
		_ = sf.Parse(rest)
		load()
		k, err := svc.Rotate(*reason)
		if err != nil {
			fatal(err)
		}
		save()
		fmt.Printf("rotated: new active key %s (reason %q)\n", k.Kid, *reason)

	case "list":
		load()
		for _, k := range svc.PublicKeys() {
			grace := "-"
			if k.GraceUntil != nil {
				grace = k.GraceUntil.Format(time.RFC3339)
			}
			fmt.Printf("%s  %-9s created %s  grace-until %s  expires %s  reason %q\n",
				k.Kid, k.Status, k.CreatedAt.Format(time.RFC3339), grace,
				k.ExpiresAt.Format(time.RFC3339), k.Reason)
		}

	case "revoke":
		sf := flag.NewFlagSet("revoke", flag.ExitOnError)
		kid := sf.String("kid", "", "key id to revoke")
		_ = sf.Parse(rest)
		if *kid == "" {
			fatal(fmt.Errorf("--kid is required"))
		}
		load()
		if err := svc.Revoke(*kid); err != nil {
			fatal(err)
		}
		save()
		fmt.Printf("revoked %s\n", *kid)

	case "sign":
		sf := flag.NewFlagSet("sign", flag.ExitOnError)
		msg := sf.String("message", "", "message to sign")
		_ = sf.Parse(rest)
		load()
		kid, sig, err := svc.Sign([]byte(*msg))
		if err != nil {
			fatal(err)
		}
		fmt.Printf("kid=%s signature_b64=%s\n", kid, base64.StdEncoding.EncodeToString(sig))

	case "verify":
		sf := flag.NewFlagSet("verify", flag.ExitOnError)
		msg := sf.String("message", "", "message that was signed")
		sigB64 := sf.String("signature", "", "base64 signature")
		kid := sf.String("kid", "", "optional: restrict to this key")
		_ = sf.Parse(rest)
		sig, err := base64.StdEncoding.DecodeString(*sigB64)
		if err != nil {
			fatal(err)
		}
		load()
		if vk, ok := svc.Verify([]byte(*msg), sig, *kid); ok {
			fmt.Printf("verified: true (kid %s)\n", vk)
		} else {
			fmt.Println("verified: false")
		}

	case "audit":
		load()
		for _, e := range svc.Audit() {
			fmt.Printf("#%d %s %-8s kid=%s reason=%q hash=%.12s…\n",
				e.Index, e.Timestamp.Format(time.RFC3339), e.Action, e.Kid, e.Reason, e.Hash)
		}

	case "audit-verify":
		load()
		if err := svc.VerifyAudit(); err != nil {
			fatal(err)
		}
		fmt.Println("audit chain: valid")

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "keyrot:", err)
	os.Exit(1)
}
