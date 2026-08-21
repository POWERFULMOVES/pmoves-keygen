package main

import (
	"path/filepath"
	"testing"

	keygen "github.com/charmbracelet/keygen"
	"golang.org/x/crypto/ssh"
)

// The unsupported-type branch used to panic with an out-of-range index rather
// than report the bad value. It was reachable only by passing exactly three
// arguments, which no test did — so build, vet and the library suite were all
// green against a guaranteed crash. These cases exist to keep that branch
// exercised.
func TestParseKeyType(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want keygen.KeyType
	}{
		{"ed25519", keygen.Ed25519},
		{"ecdsa", keygen.ECDSA},
		{"rsa", keygen.RSA},
	} {
		got, err := parseKeyType(tc.in)
		if err != nil {
			t.Fatalf("parseKeyType(%q) returned error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseKeyType(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseKeyTypeRejectsUnknown(t *testing.T) {
	for _, in := range []string{"ed25510", "ecsda", "", "ED25519"} {
		got, err := parseKeyType(in)
		if err == nil {
			t.Errorf("parseKeyType(%q) = %v, want an error", in, got)
		}
	}
}

func TestBaseName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/tmp/id_ed25519", "id_ed25519"},
		{`C:\keys\id_ed25519`, "id_ed25519"},
		{"id_ed25519", "id_ed25519"},
	} {
		if got := baseName(tc.in); got != tc.want {
			t.Errorf("baseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A blank KEYGEN_PASSPHRASE and an absent one produced identical behaviour, and
// the difference is the whole point: blank is what a secrets funnel that has
// not run leaves behind, and it wrote an UNENCRYPTED private key with nothing
// in the output to say so. Verified against ssh-keygen before these were
// written -- an encrypted=false key loads with an empty passphrase, and an
// encrypted=true key refuses one -- so `encrypted` describes the file on disk
// rather than merely echoing the variable.
func TestPassphraseState(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pass          string
		set           bool
		wantUse       string
		wantEncrypted bool
		wantWarn      bool
	}{
		{"absent: nobody asked for one", "", false, "", false, false},
		{"set but EMPTY: the funnel gap", "", true, "", false, true},
		{"populated", "hunter2", true, "hunter2", true, false},
		{"whitespace is a real passphrase, not blank", " ", true, " ", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			use, encrypted, warn := passphraseState(tc.pass, tc.set)
			if use != tc.wantUse || encrypted != tc.wantEncrypted || warn != tc.wantWarn {
				t.Errorf("passphraseState(%q, %v) = (%q, %v, %v), want (%q, %v, %v)",
					tc.pass, tc.set, use, encrypted, warn,
					tc.wantUse, tc.wantEncrypted, tc.wantWarn)
			}
		})
	}
}

// The two no-passphrase states must stay distinguishable. If this ever fails,
// the warning has been lost and the funnel gap is silent again.
func TestBlankIsNotTheSameAsAbsent(t *testing.T) {
	_, _, warnAbsent := passphraseState("", false)
	_, _, warnBlank := passphraseState("", true)
	if warnAbsent == warnBlank {
		t.Fatalf("absent and blank both warn=%v -- the distinction is gone", warnBlank)
	}
}

// keygen.New() LOADS an existing key pair rather than regenerating it, so on a
// path that already holds a key the requested type is not what is on disk.
// key_type used to report the CLI selection, producing a self-contradicting
// block: `authorized_key=ssh-rsa` beside `key_type=ed25519`. authorized_key was
// already derived from pub.Type(); only key_type was not.
func TestKeyTypeFromPublicKey(t *testing.T) {
	for _, kt := range []keygen.KeyType{keygen.Ed25519, keygen.RSA, keygen.ECDSA} {
		t.Run(string(kt), func(t *testing.T) {
			kp, err := keygen.New(filepath.Join(t.TempDir(), "k"), keygen.WithKeyType(kt))
			if err != nil {
				t.Fatalf("keygen.New(%v): %v", kt, err)
			}
			pub, err := ssh.NewPublicKey(kp.CryptoPublicKey())
			if err != nil {
				t.Fatalf("ssh.NewPublicKey: %v", err)
			}
			if got := keyTypeFromPublicKey(pub); got != string(kt) {
				t.Errorf("keyTypeFromPublicKey(%s) = %q, want %q", pub.Type(), got, kt)
			}
		})
	}
}

// The regression itself: generate RSA, then ask for the default (ed25519) on the
// same path. The reported type must follow the key on disk, not the request.
func TestExistingKeyWinsOverRequestedType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if _, err := keygen.New(path, keygen.WithKeyType(keygen.RSA), keygen.WithWrite()); err != nil {
		t.Fatalf("seed RSA: %v", err)
	}
	// Second call asks for ed25519 (the CLI default) against the existing RSA key.
	kp, err := keygen.New(path, keygen.WithKeyType(keygen.Ed25519), keygen.WithWrite())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	pub, err := ssh.NewPublicKey(kp.CryptoPublicKey())
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	got := keyTypeFromPublicKey(pub)
	if got != string(keygen.RSA) {
		t.Errorf("reported %q for an existing RSA key, want %q", got, keygen.RSA)
	}
	// And the two output lines must agree with each other: authorized_key is
	// built from pub.Type(), so a mismatch here is the self-contradicting block.
	if pub.Type() != ssh.KeyAlgoRSA {
		t.Errorf("authorized_key would say %q while key_type says %q", pub.Type(), got)
	}
}
