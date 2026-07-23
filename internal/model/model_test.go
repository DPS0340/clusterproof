package model

import (
	"encoding/json"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{input: "critical", want: SeverityCritical},
		{input: "HIGH", want: SeverityHigh},
		{input: "Medium", want: SeverityMedium},
		{input: "low", want: SeverityLow},
		{input: "info", want: SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)
			if err != nil {
				t.Fatalf("ParseSeverity(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSeverityRejectsUnknownValue(t *testing.T) {
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Fatal("ParseSeverity(urgent) succeeded, want error")
	}
}

func TestMeetsThreshold(t *testing.T) {
	if !SeverityCritical.Meets(SeverityHigh) {
		t.Fatal("critical should meet high threshold")
	}
	if !SeverityHigh.Meets(SeverityHigh) {
		t.Fatal("high should meet high threshold")
	}
	if SeverityMedium.Meets(SeverityHigh) {
		t.Fatal("medium should not meet high threshold")
	}
}

func TestFindingJSONUsesStableSeverityString(t *testing.T) {
	finding := Finding{
		ID:       "CP-K8S-001",
		Severity: SeverityHigh,
		Title:    "Privileged container",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(data) != `{"id":"CP-K8S-001","severity":"high","title":"Privileged container","description":"","remediation":"","source":"","target":"","location":{},"evidence":{},"control_refs":null}` {
		t.Fatalf("unexpected JSON: %s", data)
	}
}
