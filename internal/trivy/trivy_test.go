package trivy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kitae1645/clusterproof/internal/model"
)

func TestParseNormalizesFindingsWithoutSecretValues(t *testing.T) {
	input := `{
	  "Results": [
	    {
	      "Target": "deploy/api.yaml",
	      "Vulnerabilities": [
	        {
	          "VulnerabilityID": "CVE-2026-1234",
	          "PkgName": "openssl",
	          "InstalledVersion": "1.0.0",
	          "FixedVersion": "1.0.1",
	          "Severity": "HIGH",
	          "Title": "Example vulnerability",
	          "PrimaryURL": "https://example.invalid/CVE-2026-1234"
	        }
	      ],
	      "Misconfigurations": [
	        {
	          "ID": "KSV001",
	          "Title": "Bad configuration",
	          "Message": "configuration failed",
	          "Resolution": "Use a safe configuration",
	          "Severity": "MEDIUM",
	          "Status": "FAIL",
	          "CauseMetadata": {"StartLine": 9}
	        },
	        {
	          "ID": "KSV002",
	          "Title": "Passing configuration",
	          "Severity": "LOW",
	          "Status": "PASS"
	        }
	      ],
	      "Secrets": [
	        {
	          "RuleID": "aws-access-key-id",
	          "Category": "AWS",
	          "Severity": "CRITICAL",
	          "Title": "AWS access key",
	          "StartLine": 12,
	          "Match": "SENSITIVE_MATCH_MUST_NOT_LEAK",
	          "Code": {"Lines": [{"Number": 12, "Content": "redacted=SENSITIVE_MATCH_MUST_NOT_LEAK"}]}
	        }
	      ]
	    }
	  ]
	}`

	findings, err := Parse(strings.NewReader(input), int64(len(input)+1))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3: %#v", len(findings), findings)
	}

	vulnerability := findByID(findings, "CP-VULN-001")
	if vulnerability.Severity != model.SeverityHigh || vulnerability.ExternalRefs["vulnerability"] != "CVE-2026-1234" {
		t.Fatalf("unexpected vulnerability finding: %#v", vulnerability)
	}
	secret := findByID(findings, "CP-SECRET-001")
	if secret.Location.Line != 12 || secret.Severity != model.SeverityCritical {
		t.Fatalf("unexpected secret finding: %#v", secret)
	}

	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "SENSITIVE_MATCH_MUST_NOT_LEAK") {
		t.Fatalf("secret value leaked into findings: %s", encoded)
	}
}

func TestParseRejectsOversizedOutput(t *testing.T) {
	input := `{"Results":[]}`
	if _, err := Parse(strings.NewReader(input), 4); err == nil {
		t.Fatal("Parse succeeded, want output-limit error")
	}
}

func TestParseRejectsMalformedJSON(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"Results":`), 1024); err == nil {
		t.Fatal("Parse succeeded, want malformed JSON error")
	}
}

func TestFilesystemArgsProtectPositionalPath(t *testing.T) {
	args := FilesystemArgs("-malicious")
	if len(args) < 2 || args[len(args)-2] != "--" || args[len(args)-1] != "-malicious" {
		t.Fatalf("unsafe argument order: %#v", args)
	}
}

func TestRunFilesystemUsesBoundedDirectExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("MVP release targets darwin and linux")
	}
	root := t.TempDir()
	executable := filepath.Join(root, "fake-trivy")
	script := `#!/bin/sh
printf '%s' '{"Results":[{"Target":"repo","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1","PkgName":"lib","Severity":"HIGH"}]}]}'
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake Trivy: %v", err)
	}
	options := DefaultRunOptions()
	options.Executable = executable
	options.Timeout = time.Second
	options.MaxOutputBytes = 4096

	findings, err := RunFilesystem(context.Background(), "ignored", options)
	if err != nil {
		t.Fatalf("RunFilesystem: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "CP-VULN-001" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func findByID(findings []model.Finding, id string) model.Finding {
	for _, finding := range findings {
		if finding.ID == id {
			return finding
		}
	}
	return model.Finding{}
}
