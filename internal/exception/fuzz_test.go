package exception

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad proves hostile exception files can never panic or produce a
// partially applied suppression set.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(validFile))
	f.Add([]byte("{unclosed"))
	f.Add([]byte("schema_version: \"1\"\nexceptions: []\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "exceptions.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		entries, err := Load(path, DefaultLimits())
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.RuleID == "" || entry.Target == "" || entry.Owner == "" ||
				entry.Reason == "" || entry.Expires == "" {
				t.Fatalf("incomplete exception passed validation: %#v", entry)
			}
		}
	})
}
