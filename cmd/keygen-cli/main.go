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
		kt, err := parseKeyType(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		keyType = kt
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

// parseKeyType maps the CLI's key-type argument onto a keygen.KeyType.
//
// Extracted from main() so the unsupported-type path is reachable from a test.
// It previously lived inline and reported the failure with os.Args[3] while
// switching on os.Args[2] — and since three arguments is the only way to reach
// that branch, index 3 was always out of range, so a mistyped key type panicked
// instead of printing the message. go build, go vet and go test ./... were all
// green against it, because nothing exercised the branch.
func parseKeyType(s string) (keygen.KeyType, error) {
	switch s {
	case "ed25519":
		return keygen.Ed25519, nil
	case "ecdsa":
		return keygen.ECDSA, nil
	case "rsa":
		return keygen.RSA, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", s)
	}
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
