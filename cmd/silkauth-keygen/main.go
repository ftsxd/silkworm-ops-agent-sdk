// Command silkauth-keygen writes a new Ed25519 key pair for a platform.
//
//	silkauth-keygen -name myplatform-2026 -out ./keys
//
// It writes <name>.key (private, mode 0600, stays with the platform) and
// <name>.pub (public, handed to every service the platform will call).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	silkauth "github.com/ftsxd/silkworm-ops-agent-sdk"
)

func main() {
	name := flag.String("name", "", "key id, e.g. myplatform-2026 (required)")
	out := flag.String("out", ".", "output directory")
	flag.Parse()
	if *name == "" {
		fmt.Fprintln(os.Stderr, "-name is required")
		os.Exit(2)
	}

	pub, priv, err := silkauth.GenerateEd25519()
	if err != nil {
		fail(err)
	}
	privPEM, err := silkauth.MarshalPrivateKeyPEM(priv)
	if err != nil {
		fail(err)
	}
	pubPEM, err := silkauth.MarshalPublicKeyPEM(pub)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fail(err)
	}
	keyPath := filepath.Join(*out, *name+".key")
	pubPath := filepath.Join(*out, *name+".pub")
	// O_EXCL: never overwrite an existing private key by accident.
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(err)
	}
	if _, err := f.Write(privPEM); err != nil {
		fail(err)
	}
	if err := f.Close(); err != nil {
		fail(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("private key: %s (keep it on the platform)\npublic key:  %s (register it with the services you call)\n", keyPath, pubPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
