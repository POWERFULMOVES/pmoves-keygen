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
