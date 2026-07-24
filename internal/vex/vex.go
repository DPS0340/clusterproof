// Package vex normalizes OpenVEX status documents. A VEX status applies
// only to an exact product/vulnerability identity, and unknown or stale
// data can never silently clear a finding.
package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Limits bounds work performed on an untrusted VEX document.
type Limits struct {
	MaxBytes      int64
	MaxStatements int
	MaxText       int
}

// DefaultLimits returns conservative VEX import limits.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:      5 << 20,
		MaxStatements: 10_000,
		MaxText:       1_000,
	}
}

// Status is a normalized VEX status value.
type Status string

const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

var validStatuses = map[Status]struct{}{
	StatusNotAffected:        {},
	StatusAffected:           {},
	StatusFixed:              {},
	StatusUnderInvestigation: {},
}

// Statement is one normalized VEX assertion.
type Statement struct {
	Vulnerability string    `json:"vulnerability"`
	ProductPURL   string    `json:"product_purl"`
	Status        Status    `json:"status"`
	Justification string    `json:"justification,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// Document is one normalized VEX document.
type Document struct {
	Author     string      `json:"author"`
	Timestamp  time.Time   `json:"timestamp"`
	Statements []Statement `json:"statements"`
}

// Load reads one regular OpenVEX JSON file without following a symlink.
func Load(path string, limits Limits) (Document, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Document{}, fmt.Errorf("inspect VEX %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Document{}, fmt.Errorf("VEX %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("open VEX %q: %w", path, err)
	}
	defer file.Close()
	return Parse(file, limits)
}

// Parse normalizes one bounded OpenVEX document. Statements missing a
// vulnerability name, product identity, status, or timestamp are rejected:
// an ambiguous statement must never suppress anything.
func Parse(reader io.Reader, limits Limits) (Document, error) {
	if limits.MaxBytes <= 0 || limits.MaxStatements <= 0 || limits.MaxText <= 0 {
		return Document{}, errors.New("all VEX limits must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MaxBytes+1))
	if err != nil {
		return Document{}, fmt.Errorf("read VEX: %w", err)
	}
	if int64(len(data)) > limits.MaxBytes {
		return Document{}, fmt.Errorf("VEX exceeds limit of %d bytes", limits.MaxBytes)
	}

	var parsed struct {
		Context    string    `json:"@context"`
		Author     string    `json:"author"`
		Timestamp  time.Time `json:"timestamp"`
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Products []struct {
				Identifiers struct {
					PURL string `json:"purl"`
				} `json:"identifiers"`
			} `json:"products"`
			Status        string    `json:"status"`
			Justification string    `json:"justification"`
			Timestamp     time.Time `json:"timestamp"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Document{}, fmt.Errorf("decode VEX JSON: %w", err)
	}
	if !strings.HasPrefix(parsed.Context, "https://openvex.dev/ns") {
		return Document{}, fmt.Errorf("unsupported VEX context %q; only OpenVEX is supported", clean(parsed.Context, 200))
	}
	if len(parsed.Statements) == 0 {
		return Document{}, errors.New("VEX document contains no statements")
	}
	if len(parsed.Statements) > limits.MaxStatements {
		return Document{}, fmt.Errorf("VEX statement count exceeds limit of %d", limits.MaxStatements)
	}

	document := Document{
		Author:    clean(parsed.Author, limits.MaxText),
		Timestamp: parsed.Timestamp,
	}
	for index, statement := range parsed.Statements {
		status := Status(strings.ToLower(strings.TrimSpace(statement.Status)))
		if _, valid := validStatuses[status]; !valid {
			return Document{}, fmt.Errorf("statement %d has unsupported status %q", index+1, clean(statement.Status, 100))
		}
		vulnerability := clean(statement.Vulnerability.Name, limits.MaxText)
		if vulnerability == "" {
			return Document{}, fmt.Errorf("statement %d lacks a vulnerability name", index+1)
		}
		if status == StatusNotAffected && strings.TrimSpace(statement.Justification) == "" {
			return Document{}, fmt.Errorf(
				"statement %d: not_affected requires a justification", index+1)
		}
		timestamp := statement.Timestamp
		if timestamp.IsZero() {
			timestamp = parsed.Timestamp
		}
		if timestamp.IsZero() {
			return Document{}, fmt.Errorf("statement %d lacks a timestamp", index+1)
		}
		if len(statement.Products) == 0 {
			return Document{}, fmt.Errorf("statement %d lists no products; a VEX status must bind an exact product", index+1)
		}
		for productIndex, product := range statement.Products {
			purl := clean(product.Identifiers.PURL, limits.MaxText)
			if purl == "" {
				return Document{}, fmt.Errorf(
					"statement %d product %d lacks a purl identity", index+1, productIndex+1)
			}
			document.Statements = append(document.Statements, Statement{
				Vulnerability: vulnerability,
				ProductPURL:   purl,
				Status:        status,
				Justification: clean(statement.Justification, limits.MaxText),
				Timestamp:     timestamp.UTC(),
			})
		}
	}
	sort.Slice(document.Statements, func(i, j int) bool {
		if document.Statements[i].Vulnerability != document.Statements[j].Vulnerability {
			return document.Statements[i].Vulnerability < document.Statements[j].Vulnerability
		}
		return document.Statements[i].ProductPURL < document.Statements[j].ProductPURL
	})
	return document, nil
}

// SuppressionFor returns the statement justifying suppression of one exact
// vulnerability/product pair, if any. Only not_affected and fixed suppress,
// only an exact match applies, and a statement older than maxAge is stale
// and never suppresses.
func (d Document) SuppressionFor(vulnerability, productPURL string, now time.Time, maxAge time.Duration) (Statement, bool) {
	for _, statement := range d.Statements {
		if statement.Vulnerability != vulnerability || statement.ProductPURL != productPURL {
			continue
		}
		if statement.Status != StatusNotAffected && statement.Status != StatusFixed {
			continue
		}
		if maxAge > 0 && now.Sub(statement.Timestamp) > maxAge {
			continue // stale VEX data cannot silently clear a finding
		}
		return statement, true
	}
	return Statement{}, false
}

func clean(value string, maxLength int) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, current := range value {
		if builder.Len() >= maxLength {
			break
		}
		if unicode.IsControl(current) {
			builder.WriteRune(' ')
			continue
		}
		builder.WriteRune(current)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}
