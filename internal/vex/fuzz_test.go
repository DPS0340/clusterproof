package vex

import (
	"strings"
	"testing"
	"time"
)

// FuzzParse proves hostile VEX documents can never panic and no accepted
// statement is ever missing the identity fields suppression depends on.
func FuzzParse(f *testing.F) {
	f.Add([]byte(validVEX))
	f.Add([]byte("{unclosed"))
	f.Add([]byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		document, err := Parse(strings.NewReader(string(data)), DefaultLimits())
		if err != nil {
			return
		}
		now := time.Now().UTC()
		for _, statement := range document.Statements {
			if statement.Vulnerability == "" || statement.ProductPURL == "" {
				t.Fatalf("statement without identity passed validation: %#v", statement)
			}
			if statement.Timestamp.IsZero() {
				t.Fatalf("statement without timestamp passed validation: %#v", statement)
			}
			if statement.Status == StatusNotAffected && statement.Justification == "" {
				t.Fatalf("unjustified not_affected passed validation: %#v", statement)
			}
			_ = now
		}
	})
}
