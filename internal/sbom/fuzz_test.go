package sbom

import (
	"strings"
	"testing"
)

// FuzzParse proves hostile SBOM documents can never panic and normalized
// packages never carry control characters.
func FuzzParse(f *testing.F) {
	f.Add([]byte(spdxDocument))
	f.Add([]byte(cycloneDXDocument))
	f.Add([]byte("{unclosed"))
	f.Add([]byte(`{"spdxVersion": "SPDX-2.3", "packages": [{"name": "\u0000evil"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		document, err := Parse(strings.NewReader(string(data)), DefaultLimits())
		if err != nil {
			return
		}
		for _, entry := range document.Packages {
			if strings.ContainsAny(entry.Name+entry.Version+entry.PURL+entry.License, "\x00\x1b\n\r") {
				t.Fatalf("control characters escaped sanitization: %#v", entry)
			}
		}
	})
}
