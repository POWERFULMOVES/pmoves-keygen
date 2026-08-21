package main

import (
	"testing"

	keygen "github.com/charmbracelet/keygen"
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
