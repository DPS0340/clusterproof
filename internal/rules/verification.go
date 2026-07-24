package rules

import (
	"github.com/DPS0340/clusterproof/internal/model"
)

// UnpinnedImageFinding reports an image that cannot be signature verified
// because it lacks a digest. Kept in the rules package so the catalog
// drift tests cover the exact emitted metadata.
func UnpinnedImageFinding(target, rawReference string) model.Finding {
	return verificationFinding(
		"CP-SUPPLY-003",
		model.SeverityMedium,
		target,
		model.Evidence{
			Observed: "unpinned reference " + rawReference,
			Expected: "digest-pinned reference",
		},
	)
}

// SignatureFailedFinding reports a digest-pinned image whose signature did
// not satisfy the pinned trust policy.
func SignatureFailedFinding(target, failureCause string) model.Finding {
	return verificationFinding(
		"CP-SUPPLY-004",
		model.SeverityHigh,
		target,
		model.Evidence{
			Observed: failureCause,
			Expected: "signature matching the pinned trust policy",
		},
	)
}

func verificationFinding(id string, severity model.Severity, target string, evidence model.Evidence) model.Finding {
	definition, _ := DefaultCatalog().FindRule(id)
	return model.Finding{
		ID:          id,
		Severity:    severity,
		Title:       definition.Title,
		Description: definition.Description,
		Remediation: definition.Remediation,
		Source:      "clusterproof",
		Target:      target,
		Evidence:    evidence,
		ControlRefs: append([]string(nil), definition.ControlRefs...),
		ExternalRefs: map[string]string{
			"guidance": "https://docs.sigstore.dev/cosign/verifying/verify/",
		},
	}
}
