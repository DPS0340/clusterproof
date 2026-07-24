// Package exception applies repository-owned, time-bounded finding
// suppressions without hiding suppressed finding identity from evidence.
package exception

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DPS0340/clusterproof/internal/model"
	"gopkg.in/yaml.v3"
)

// Limits bounds work performed on an untrusted exception file.
type Limits struct {
	MaxFileBytes int64
	MaxEntries   int
	MaxTextBytes int
}

// DefaultLimits returns conservative limits for a repository exception file.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes: 1 << 20,
		MaxEntries:   500,
		MaxTextBytes: 1_000,
	}
}

// Exception is one reviewed, expiring suppression of an exact finding scope.
type Exception struct {
	RuleID  string `yaml:"rule" json:"rule"`
	Target  string `yaml:"target" json:"target"`
	Owner   string `yaml:"owner" json:"owner"`
	Reason  string `yaml:"reason" json:"reason"`
	Expires string `yaml:"expires" json:"expires"`
}

type file struct {
	SchemaVersion string      `yaml:"schema_version"`
	Exceptions    []Exception `yaml:"exceptions"`
}

// Load parses and validates one bounded exception file. Malformed files fail
// as a whole: a partially valid file must never silently suppress findings.
func Load(path string, limits Limits) ([]Exception, error) {
	if limits.MaxFileBytes <= 0 || limits.MaxEntries <= 0 || limits.MaxTextBytes <= 0 {
		return nil, errors.New("all exception limits must be positive")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect exception file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("exception file %q is not a regular file", path)
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open exception file %q: %w", path, err)
	}
	defer handle.Close()

	data, err := io.ReadAll(io.LimitReader(handle, limits.MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read exception file %q: %w", path, err)
	}
	if int64(len(data)) > limits.MaxFileBytes {
		return nil, fmt.Errorf("exception file %q exceeds limit of %d bytes", path, limits.MaxFileBytes)
	}

	var parsed file
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode exception file %q: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("exception file %q must contain exactly one document", path)
	}
	if parsed.SchemaVersion != "1" {
		return nil, fmt.Errorf("unsupported exception schema version %q", parsed.SchemaVersion)
	}
	if len(parsed.Exceptions) == 0 {
		return nil, fmt.Errorf("exception file %q lists no exceptions", path)
	}
	if len(parsed.Exceptions) > limits.MaxEntries {
		return nil, fmt.Errorf("exception file %q exceeds entry limit of %d", path, limits.MaxEntries)
	}

	seen := make(map[string]struct{}, len(parsed.Exceptions))
	for index, entry := range parsed.Exceptions {
		if err := validate(entry, limits.MaxTextBytes); err != nil {
			return nil, fmt.Errorf("exception %d in %q: %w", index+1, path, err)
		}
		key := entry.RuleID + "\x00" + entry.Target
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("exception %d in %q duplicates rule %s for target %s",
				index+1, path, entry.RuleID, entry.Target)
		}
		seen[key] = struct{}{}
	}
	return parsed.Exceptions, nil
}

func validate(entry Exception, maxTextBytes int) error {
	for name, value := range map[string]string{
		"rule":    entry.RuleID,
		"target":  entry.Target,
		"owner":   entry.Owner,
		"reason":  entry.Reason,
		"expires": entry.Expires,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("field %q is required", name)
		}
		if len(value) > maxTextBytes {
			return fmt.Errorf("field %q exceeds limit of %d bytes", name, maxTextBytes)
		}
		if strings.ContainsAny(value, "\x00\n\r") {
			return fmt.Errorf("field %q contains control characters", name)
		}
	}
	if _, err := time.Parse("2006-01-02", entry.Expires); err != nil {
		return fmt.Errorf("field \"expires\" must be a UTC date like 2026-12-31: %w", err)
	}
	return nil
}

// Apply partitions findings into kept and suppressed sets. Only an exact
// rule-and-target match with an unexpired exception suppresses a finding.
// now must be UTC; an exception expires at the end of its stated date.
func Apply(findings []model.Finding, exceptions []Exception, now time.Time) ([]model.Finding, []model.SuppressedFinding) {
	if len(exceptions) == 0 {
		return findings, nil
	}
	active := make(map[string]Exception, len(exceptions))
	for _, entry := range exceptions {
		expiry, err := time.Parse("2006-01-02", entry.Expires)
		if err != nil {
			continue // Load rejects this; never suppress on a malformed date.
		}
		if !now.Before(expiry.AddDate(0, 0, 1)) {
			continue // expired exceptions must not suppress findings
		}
		active[entry.RuleID+"\x00"+entry.Target] = entry
	}

	kept := make([]model.Finding, 0, len(findings))
	var suppressed []model.SuppressedFinding
	for _, finding := range findings {
		entry, matched := active[finding.ID+"\x00"+finding.Target]
		if !matched {
			kept = append(kept, finding)
			continue
		}
		suppressed = append(suppressed, model.SuppressedFinding{
			RuleID:   finding.ID,
			Severity: finding.Severity,
			Target:   finding.Target,
			Owner:    entry.Owner,
			Reason:   entry.Reason,
			Expires:  entry.Expires,
			Location: model.Location{
				Path:      finding.Location.Path,
				Container: finding.Location.Container,
			},
		})
	}
	sort.Slice(suppressed, func(i, j int) bool {
		if suppressed[i].RuleID != suppressed[j].RuleID {
			return suppressed[i].RuleID < suppressed[j].RuleID
		}
		if suppressed[i].Target != suppressed[j].Target {
			return suppressed[i].Target < suppressed[j].Target
		}
		return suppressed[i].Location.Container < suppressed[j].Location.Container
	})
	return kept, suppressed
}
