package trust

import (
	"strings"
	"testing"
)

// FuzzParse proves hostile trust policies can never panic and that private
// key material is always rejected regardless of surrounding structure.
func FuzzParse(f *testing.F) {
	f.Add([]byte(validPolicy))
	f.Add([]byte("{unclosed"))
	f.Add([]byte("schema_version: \"1\"\nkeys:\n  - name: k\n    public_key_pem: \"-----BEGIN PRIVATE KEY-----\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		policy, err := Parse(data, DefaultLimits())
		if err != nil {
			return
		}
		for _, key := range policy.Keys {
			if key.PublicKeyPEM != "" && !strings.Contains(key.PublicKeyPEM, "BEGIN PUBLIC KEY") {
				t.Fatalf("non-public key material passed validation: %q", key.Name)
			}
		}
		for _, identity := range policy.Identities {
			if identity.Subject == "" || identity.Issuer == "" {
				t.Fatalf("incomplete identity passed validation: %#v", identity)
			}
		}
	})
}
