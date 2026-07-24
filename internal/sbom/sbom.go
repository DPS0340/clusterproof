// Package sbom imports bounded SPDX and CycloneDX inventories without
// turning the absence of a vulnerability record into proof of safety.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"
)

// Format identifies a supported SBOM document format.
type Format string

const (
	// FormatSPDX is SPDX JSON (spdxVersion SPDX-2.2 or SPDX-2.3).
	FormatSPDX Format = "spdx"
	// FormatCycloneDX is CycloneDX JSON (specVersion 1.4 through 1.6).
	FormatCycloneDX Format = "cyclonedx"
)

// Limits bounds work performed on an untrusted SBOM document.
type Limits struct {
	MaxBytes    int64
	MaxPackages int
	MaxText     int
}

// DefaultLimits returns conservative SBOM import limits.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:    50 << 20,
		MaxPackages: 50_000,
		MaxText:     1_000,
	}
}

// Package is one normalized SBOM component.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	License string `json:"license,omitempty"`
}

// Document is one normalized SBOM inventory.
type Document struct {
	Format        Format    `json:"format"`
	SpecVersion   string    `json:"spec_version"`
	Packages      []Package `json:"packages"`
	InputSHA256   string    `json:"input_sha256,omitempty"`
	AdapterNotice string    `json:"adapter_notice"`
}

// Notice is attached to every imported document so consumers never treat
// an inventory as a vulnerability assessment.
const Notice = "SBOM inventory only; the absence of a vulnerability record is not evidence of safety."

var supportedSPDXVersions = map[string]struct{}{
	"SPDX-2.2": {},
	"SPDX-2.3": {},
}

var supportedCycloneDXVersions = map[string]struct{}{
	"1.4": {},
	"1.5": {},
	"1.6": {},
}

// Load reads one regular SBOM JSON file without following a symlink.
func Load(path string, limits Limits) (Document, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Document{}, fmt.Errorf("inspect SBOM %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Document{}, fmt.Errorf("SBOM %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Document{}, fmt.Errorf("open SBOM %q: %w", path, err)
	}
	defer file.Close()
	return Parse(file, limits)
}

// Parse detects and normalizes one bounded SPDX or CycloneDX JSON document.
func Parse(reader io.Reader, limits Limits) (Document, error) {
	if limits.MaxBytes <= 0 || limits.MaxPackages <= 0 || limits.MaxText <= 0 {
		return Document{}, errors.New("all SBOM limits must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MaxBytes+1))
	if err != nil {
		return Document{}, fmt.Errorf("read SBOM: %w", err)
	}
	if int64(len(data)) > limits.MaxBytes {
		return Document{}, fmt.Errorf("SBOM exceeds limit of %d bytes", limits.MaxBytes)
	}

	var probe struct {
		SPDXVersion string `json:"spdxVersion"`
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Document{}, fmt.Errorf("decode SBOM JSON: %w", err)
	}

	switch {
	case probe.SPDXVersion != "":
		if _, supported := supportedSPDXVersions[probe.SPDXVersion]; !supported {
			return Document{}, fmt.Errorf("unsupported SPDX version %q; supported: SPDX-2.2, SPDX-2.3", clean(probe.SPDXVersion, 100))
		}
		return parseSPDX(data, probe.SPDXVersion, limits)
	case probe.BOMFormat == "CycloneDX":
		if _, supported := supportedCycloneDXVersions[probe.SpecVersion]; !supported {
			return Document{}, fmt.Errorf("unsupported CycloneDX specVersion %q; supported: 1.4, 1.5, 1.6", clean(probe.SpecVersion, 100))
		}
		return parseCycloneDX(data, probe.SpecVersion, limits)
	default:
		return Document{}, errors.New("input is neither SPDX (spdxVersion) nor CycloneDX (bomFormat) JSON")
	}
}

func parseSPDX(data []byte, version string, limits Limits) (Document, error) {
	var parsed struct {
		Packages []struct {
			Name             string `json:"name"`
			Version          string `json:"versionInfo"`
			LicenseConcluded string `json:"licenseConcluded"`
			ExternalRefs     []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Document{}, fmt.Errorf("decode SPDX packages: %w", err)
	}
	if len(parsed.Packages) > limits.MaxPackages {
		return Document{}, fmt.Errorf("SPDX package count exceeds limit of %d", limits.MaxPackages)
	}

	document := Document{Format: FormatSPDX, SpecVersion: version, AdapterNotice: Notice}
	for _, spdxPackage := range parsed.Packages {
		normalized := Package{
			Name:    clean(spdxPackage.Name, limits.MaxText),
			Version: clean(spdxPackage.Version, limits.MaxText),
			License: clean(spdxPackage.LicenseConcluded, limits.MaxText),
		}
		for _, ref := range spdxPackage.ExternalRefs {
			if ref.ReferenceType == "purl" {
				normalized.PURL = clean(ref.ReferenceLocator, limits.MaxText)
				break
			}
		}
		if normalized.Name == "" {
			continue
		}
		document.Packages = append(document.Packages, normalized)
	}
	normalize(&document)
	return document, nil
}

func parseCycloneDX(data []byte, version string, limits Limits) (Document, error) {
	var parsed struct {
		Components []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Document{}, fmt.Errorf("decode CycloneDX components: %w", err)
	}
	if len(parsed.Components) > limits.MaxPackages {
		return Document{}, fmt.Errorf("CycloneDX component count exceeds limit of %d", limits.MaxPackages)
	}

	document := Document{Format: FormatCycloneDX, SpecVersion: version, AdapterNotice: Notice}
	for _, component := range parsed.Components {
		normalized := Package{
			Name:    clean(component.Name, limits.MaxText),
			Version: clean(component.Version, limits.MaxText),
			PURL:    clean(component.PURL, limits.MaxText),
		}
		for _, licenseEntry := range component.Licenses {
			license := licenseEntry.License.ID
			if license == "" {
				license = licenseEntry.License.Name
			}
			if license != "" {
				normalized.License = clean(license, limits.MaxText)
				break
			}
		}
		if normalized.Name == "" {
			continue
		}
		document.Packages = append(document.Packages, normalized)
	}
	normalize(&document)
	return document, nil
}

func normalize(document *Document) {
	sort.Slice(document.Packages, func(i, j int) bool {
		if document.Packages[i].Name != document.Packages[j].Name {
			return document.Packages[i].Name < document.Packages[j].Name
		}
		if document.Packages[i].Version != document.Packages[j].Version {
			return document.Packages[i].Version < document.Packages[j].Version
		}
		return document.Packages[i].PURL < document.Packages[j].PURL
	})
	deduplicated := document.Packages[:0]
	var previous Package
	for index, current := range document.Packages {
		if index == 0 || current != previous {
			deduplicated = append(deduplicated, current)
		}
		previous = current
	}
	document.Packages = deduplicated
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
