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
	// A BLANK KEYGEN_PASSPHRASE is not the same as an absent one, but the
	// original treated them identically -- and blank is the likelier accident.
	// A secrets funnel that has not run, or has a gap for this key, exports the
	// variable with an EMPTY value; the key is then written UNENCRYPTED and
	// nothing in the output says so. For tooling that mints fleet signing
	// identities, a silently unprotected private key at rest is worth being
	// loud about.
	pass, encrypted, warnBlank := passphraseState(os.LookupEnv("KEYGEN_PASSPHRASE"))
	if encrypted {
		opts = append(opts, keygen.WithPassphrase(pass))
	}
	if warnBlank {
		fmt.Fprintln(os.Stderr,
			"keygen-cli: WARNING KEYGEN_PASSPHRASE is set but EMPTY -- writing an "+
				"UNENCRYPTED private key. If the value was meant to be there it did "+
				"not reach this process; check `make -C pmoves secrets-funnel`.")
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
	// Emitted so the consumer can ASSERT the protection state instead of
	// assuming it. Without this line there is no way to tell an intentionally
	// unencrypted key from one whose passphrase went missing.
	fmt.Printf("encrypted=%t\n", encrypted)
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

// passphraseState decides what to do with KEYGEN_PASSPHRASE, given the raw
// os.LookupEnv result. Extracted from main() for the same reason parseKeyType
// was: the branch that matters is unreachable from a test while it lives
// inline, and an untested branch here writes an unprotected private key.
//
// The three states are deliberately distinct. Absent means nobody asked for a
// passphrase. Set-but-empty means somebody DID and the value did not arrive --
// the secrets-funnel gap -- and is the only one that warrants a warning.
func passphraseState(pass string, set bool) (use string, encrypted, warnBlank bool) {
	if pass != "" {
		return pass, true, false
	}
	return "", false, set
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
