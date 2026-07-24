package sigstore

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/image"
	"github.com/DPS0340/clusterproof/internal/trust"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func pinnedReference() image.Reference {
	return image.Reference{
		Raw:        "ghcr.io/example/app@" + testDigest,
		Registry:   "ghcr.io",
		Repository: "example/app",
		Digest:     testDigest,
	}
}

func keylessPolicy() trust.Policy {
	return trust.Policy{
		SchemaVersion: "1",
		Identities: []trust.Identity{{
			Subject: "https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0",
			Issuer:  "https://token.actions.githubusercontent.com",
		}},
	}
}

func writeBundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func writeFakeCosign(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-cosign")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	return path
}

func TestVerifyArgsContract(t *testing.T) {
	identity := trust.Identity{Subject: "subject", Issuer: "https://issuer.example.com"}
	options := DefaultOptions()
	options.BundlePath = "/tmp/bundle.json"

	got := VerifyArgs("ghcr.io/example/app@"+testDigest, &identity, nil, options)
	want := []string{
		"verify", "--output", "json",
		"--certificate-identity", "subject",
		"--certificate-oidc-issuer", "https://issuer.example.com",
		"--bundle", "/tmp/bundle.json",
		"--offline", "--private-infrastructure",
		"--", "ghcr.io/example/app@" + testDigest,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("VerifyArgs() = %#v, want %#v", got, want)
	}

	key := trust.Key{Name: "release", Path: "/tmp/key.pub"}
	online := DefaultOptions()
	online.AllowNetwork = true
	got = VerifyArgs("ref", nil, &key, online)
	want = []string{"verify", "--output", "json", "--key", "/tmp/key.pub", "--", "ref"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("VerifyArgs(key, online) = %#v, want %#v", got, want)
	}
}

func TestVerifyRefusesFloatingTags(t *testing.T) {
	floating := image.Reference{Raw: "ghcr.io/example/app:latest", Registry: "ghcr.io", Repository: "example/app", Tag: "latest"}
	_, err := Verify(context.Background(), floating, keylessPolicy(), DefaultOptions())
	if err == nil || !strings.Contains(err.Error(), "floating tag") {
		t.Fatalf("floating tag accepted: %v", err)
	}
}

func TestVerifyOfflineRequiresBundle(t *testing.T) {
	options := DefaultOptions() // AllowNetwork=false, no bundle
	_, err := Verify(context.Background(), pinnedReference(), keylessPolicy(), options)
	if err == nil || !strings.Contains(err.Error(), "bundle") {
		t.Fatalf("offline verification without bundle accepted: %v", err)
	}
}

func TestVerifyRefusesEmptyPolicy(t *testing.T) {
	options := DefaultOptions()
	options.BundlePath = writeBundle(t)
	_, err := Verify(context.Background(), pinnedReference(), trust.Policy{SchemaVersion: "1"}, options)
	if err == nil || !strings.Contains(err.Error(), "no identity or key") {
		t.Fatalf("empty policy accepted: %v", err)
	}
}

func TestVerifySucceedsWithValidClaims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	options := DefaultOptions()
	options.BundlePath = writeBundle(t)
	options.Executable = writeFakeCosign(t, `#!/bin/sh
printf '[{"critical":{"identity":{"docker-reference":"ghcr.io/example/app"}}}]'
`)
	verification, err := Verify(context.Background(), pinnedReference(), keylessPolicy(), options)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verification.Verified || verification.Mode != "keyless" {
		t.Fatalf("verification = %#v", verification)
	}
	if verification.NetworkUsed || !verification.Offline {
		t.Fatalf("offline run recorded network use: %#v", verification)
	}
	if verification.Identity == "" || verification.Issuer == "" {
		t.Fatalf("identity metadata missing: %#v", verification)
	}
}

func TestVerifyFailsClosedOnRejectionEmptyClaimsAndOversizedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	tests := []struct {
		name   string
		script string
		limit  int64
	}{
		{
			name: "cosign rejects signature",
			script: `#!/bin/sh
echo "Error: no matching signatures" >&2
exit 1
`,
		},
		{
			name: "empty claim list",
			script: `#!/bin/sh
printf '[]'
`,
		},
		{
			name: "non-JSON output",
			script: `#!/bin/sh
printf 'ok'
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := DefaultOptions()
			options.BundlePath = writeBundle(t)
			options.Executable = writeFakeCosign(t, test.script)

			verification, err := Verify(context.Background(), pinnedReference(), keylessPolicy(), options)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if verification.Verified {
				t.Fatalf("verification succeeded for %s: %#v", test.name, verification)
			}
			if verification.FailureCause == "" {
				t.Fatal("failure cause missing")
			}
		})
	}
}

func TestVerifyOversizedOutputFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	options := DefaultOptions()
	options.BundlePath = writeBundle(t)
	options.MaxOutputBytes = 8
	options.Executable = writeFakeCosign(t, `#!/bin/sh
printf '[{"claim": "this output is longer than eight bytes"}]'
`)
	if _, err := Verify(context.Background(), pinnedReference(), keylessPolicy(), options); err == nil ||
		!strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized output accepted: %v", err)
	}
}

func TestVerifyRejectsSymlinkBundle(t *testing.T) {
	real := writeBundle(t)
	link := filepath.Join(t.TempDir(), "bundle-link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	options := DefaultOptions()
	options.BundlePath = link
	_, err := Verify(context.Background(), pinnedReference(), keylessPolicy(), options)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked bundle accepted: %v", err)
	}
}
