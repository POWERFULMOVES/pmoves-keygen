// Command keygen-cli generates an SSH key pair at the given path (the path is
// the private-key file itself; the public key lands at <path>.pub) and prints
// the artifacts PMOVES signing-card tooling needs: the authorized key line,
// the SHA256 fingerprint, and the key type.
//
// The private key is optionally protected by a passphrase read from the
// KEYGEN_PASSPHRASE environment variable (never a CLI argument, so it never
// lands in shell history or process listings).
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	keygen "github.com/charmbracelet/keygen"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: keygen-cli <key-path> [ed25519|ecdsa|rsa]")
		os.Exit(2)
	}
	path := os.Args[1]
	name := baseName(path)

	keyType := keygen.Ed25519
	if len(os.Args) > 2 {
		switch os.Args[2] {
		case "ed25519":
			keyType = keygen.Ed25519
		case "ecdsa":
			keyType = keygen.ECDSA
		case "rsa":
			keyType = keygen.RSA
		default:
			fmt.Fprintf(os.Stderr, "unsupported key type: %s\n", os.Args[3])
			os.Exit(2)
		}
	}

	opts := []keygen.Option{keygen.WithKeyType(keyType), keygen.WithWrite()}
	if pass := os.Getenv("KEYGEN_PASSPHRASE"); pass != "" {
		opts = append(opts, keygen.WithPassphrase(pass))
	}

	kp, err := keygen.New(path, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}

	pub, err := ssh.NewPublicKey(kp.CryptoPublicKey())
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubkey: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("authorized_key=%s %s %s\n",
		pub.Type(), base64.StdEncoding.EncodeToString(pub.Marshal()), name)
	fmt.Printf("fingerprint=%s\n", ssh.FingerprintSHA256(pub))
	fmt.Printf("key_type=%s\n", keyType)
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
