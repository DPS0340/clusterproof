package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spdxDocument = `{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "zlib",
      "versionInfo": "1.3.1",
      "licenseConcluded": "Zlib",
      "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:generic/zlib@1.3.1"}
      ]
    },
    {"name": "openssl", "versionInfo": "3.3.0"},
    {"name": "zlib", "versionInfo": "1.3.1", "licenseConcluded": "Zlib",
     "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:generic/zlib@1.3.1"}]}
  ]
}`

const cycloneDXDocument = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "name": "left-pad",
      "version": "1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}`

func TestParseSPDXNormalizesAndDeduplicates(t *testing.T) {
	document, err := Parse(strings.NewReader(spdxDocument), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if document.Format != FormatSPDX || document.SpecVersion != "SPDX-2.3" {
		t.Fatalf("document identity = %#v", document)
	}
	if len(document.Packages) != 2 {
		t.Fatalf("packages = %#v, want 2 after deduplication", document.Packages)
	}
	if document.Packages[0].Name != "openssl" || document.Packages[1].PURL != "pkg:generic/zlib@1.3.1" {
		t.Fatalf("packages not sorted/normalized: %#v", document.Packages)
	}
	if !strings.Contains(document.AdapterNotice, "not evidence of safety") {
		t.Fatalf("missing adapter notice: %q", document.AdapterNotice)
	}
}

func TestParseCycloneDX(t *testing.T) {
	document, err := Parse(strings.NewReader(cycloneDXDocument), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if document.Format != FormatCycloneDX || len(document.Packages) != 1 {
		t.Fatalf("document = %#v", document)
	}
	if document.Packages[0].License != "MIT" || document.Packages[0].PURL != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("package = %#v", document.Packages[0])
	}
}

func TestParseRejectsUnsupportedInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "unsupported SPDX version", input: `{"spdxVersion": "SPDX-1.2", "packages": []}`},
		{name: "unsupported CycloneDX version", input: `{"bomFormat": "CycloneDX", "specVersion": "1.0"}`},
		{name: "neither format", input: `{"hello": "world"}`},
		{name: "malformed JSON", input: `{unclosed`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(test.input), DefaultLimits()); err == nil {
				t.Fatal("Parse succeeded for unsupported input")
			}
		})
	}
}

func TestParseLimitsFailClosed(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBytes = 16
	if _, err := Parse(strings.NewReader(spdxDocument), limits); err == nil {
		t.Fatal("oversized SBOM accepted")
	}

	limits = DefaultLimits()
	limits.MaxPackages = 1
	if _, err := Parse(strings.NewReader(spdxDocument), limits); err == nil {
		t.Fatal("package count above limit accepted")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	real := filepath.Join(directory, "sbom.json")
	if err := os.WriteFile(real, []byte(spdxDocument), 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := Load(link, DefaultLimits()); err == nil {
		t.Fatal("symlinked SBOM accepted")
	}
}

func TestParseSanitizesHostileText(t *testing.T) {
	hostile := `{
	  "spdxVersion": "SPDX-2.3",
	  "packages": [{"name": "evil\u0000\u001b[31mpackage", "versionInfo": "1.0"}]
	}`
	document, err := Parse(strings.NewReader(hostile), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if strings.ContainsAny(document.Packages[0].Name, "\x00\x1b") {
		t.Fatalf("control characters not sanitized: %q", document.Packages[0].Name)
	}
}
