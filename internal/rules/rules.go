// Package rules evaluates normalized workloads without performing I/O.
package rules

import (
	"sort"
	"strings"

	"github.com/kitae1645/clusterproof/internal/manifest"
	"github.com/kitae1645/clusterproof/internal/model"
)

var severityRank = map[model.Severity]int{
	model.SeverityInfo:     0,
	model.SeverityLow:      1,
	model.SeverityMedium:   2,
	model.SeverityHigh:     3,
	model.SeverityCritical: 4,
}

// Evaluate runs native Kubernetes posture and image-integrity rules.
func Evaluate(workload manifest.Workload) []model.Finding {
	findings := evaluatePod(workload)
	for _, container := range workload.PodSpec.AllContainers() {
		findings = append(findings, evaluateContainer(workload, container)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank[findings[i].Severity] > severityRank[findings[j].Severity]
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Location.Container < findings[j].Location.Container
	})
	return findings
}

func evaluatePod(workload manifest.Workload) []model.Finding {
	var findings []model.Finding
	spec := workload.PodSpec

	var namespaces []string
	if spec.HostNetwork {
		namespaces = append(namespaces, "hostNetwork")
	}
	if spec.HostPID {
		namespaces = append(namespaces, "hostPID")
	}
	if spec.HostIPC {
		namespaces = append(namespaces, "hostIPC")
	}
	if len(namespaces) > 0 {
		findings = append(findings, finding(
			workload,
			"CP-K8S-002",
			model.SeverityHigh,
			"Host namespace sharing enabled",
			"Sharing host namespaces weakens workload isolation and can expose node-level processes or networking.",
			"Disable hostNetwork, hostPID, and hostIPC unless the workload has a reviewed infrastructure exception.",
			model.Evidence{Observed: strings.Join(namespaces, ", "), Expected: "host namespaces disabled"},
			"SOC2:CC6", "Kubernetes:PSS-Baseline",
		))
	}

	for _, volume := range spec.Volumes {
		if volume.HostPath == nil {
			continue
		}
		findings = append(findings, finding(
			workload,
			"CP-K8S-003",
			model.SeverityHigh,
			"Host filesystem mounted into workload",
			"A hostPath volume can expose node files and turn a container compromise into a node compromise.",
			"Replace hostPath with a restricted volume type or document and enforce a narrow exception.",
			model.Evidence{Observed: "hostPath volume " + volume.Name, Expected: "restricted volume type"},
			"SOC2:CC6", "Kubernetes:PSS-Restricted",
		))
	}

	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		findings = append(findings, finding(
			workload,
			"CP-K8S-010",
			model.SeverityMedium,
			"Service account token is automatically mounted",
			"An unnecessary Kubernetes API credential increases the impact of a container compromise.",
			"Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.",
			model.Evidence{Observed: "token automount enabled or implicit", Expected: "automountServiceAccountToken: false"},
			"SOC2:CC6", "Kubernetes:Security-Checklist",
		))
	}
	return findings
}

func evaluateContainer(workload manifest.Workload, container manifest.Container) []model.Finding {
	var findings []model.Finding
	context := container.SecurityContext

	if context.Privileged != nil && *context.Privileged {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-001", model.SeverityCritical,
			"Privileged container",
			"Privileged containers bypass major isolation controls and can commonly reach the node.",
			"Set securityContext.privileged: false and grant only the specific capability required.",
			model.Evidence{Observed: "privileged: true", Expected: "privileged: false"},
			"SOC2:CC6", "Kubernetes:PSS-Baseline",
		))
	}

	if context.AllowPrivilegeEscalation == nil || *context.AllowPrivilegeEscalation {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-004", model.SeverityHigh,
			"Privilege escalation is not disabled",
			"The container may gain more privileges than its parent process.",
			"Set securityContext.allowPrivilegeEscalation: false.",
			model.Evidence{Observed: "true or implicit default", Expected: "allowPrivilegeEscalation: false"},
			"SOC2:CC6", "Kubernetes:PSS-Restricted",
		))
	}

	if severity, observed, unsafe := nonRootRisk(workload.PodSpec.SecurityContext, context); unsafe {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-005", severity,
			"Non-root execution is not guaranteed",
			"Root execution increases the impact of a container escape or writable filesystem weakness.",
			"Set runAsNonRoot: true and use a non-zero runAsUser where the image requires an explicit UID.",
			model.Evidence{Observed: observed, Expected: "runAsNonRoot: true"},
			"SOC2:CC6", "Kubernetes:PSS-Restricted",
		))
	}

	if severity, observed, unsafe := seccompRisk(workload.PodSpec.SecurityContext, context); unsafe {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-006", severity,
			"Seccomp isolation is not enforced",
			"A missing or unconfined seccomp profile leaves unnecessary kernel syscalls available.",
			"Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile.",
			model.Evidence{Observed: observed, Expected: "RuntimeDefault or Localhost"},
			"SOC2:CC6", "Kubernetes:PSS-Baseline",
		))
	}

	if capabilities := unexpectedCapabilities(context.Capabilities.Add); len(capabilities) > 0 {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-007", model.SeverityHigh,
			"Additional Linux capabilities requested",
			"Powerful Linux capabilities can provide host-level actions without a fully privileged container.",
			"Remove added capabilities; if required, allow only NET_BIND_SERVICE after review.",
			model.Evidence{Observed: strings.Join(capabilities, ", "), Expected: "no added capabilities"},
			"SOC2:CC6", "Kubernetes:PSS-Restricted",
		))
	}

	if !containsFold(context.Capabilities.Drop, "ALL") {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-008", model.SeverityMedium,
			"Default Linux capabilities are not dropped",
			"The runtime capability set is broader than most applications require.",
			"Set securityContext.capabilities.drop to [ALL], then add back only reviewed requirements.",
			model.Evidence{Observed: "drop ALL absent", Expected: "capabilities.drop: [ALL]"},
			"SOC2:CC6", "Kubernetes:PSS-Restricted",
		))
	}

	if context.ReadOnlyRootFilesystem == nil || !*context.ReadOnlyRootFilesystem {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-K8S-009", model.SeverityMedium,
			"Container root filesystem is writable",
			"A writable image filesystem gives an attacker persistence space inside the running container.",
			"Set readOnlyRootFilesystem: true and mount explicit writable volumes where required.",
			model.Evidence{Observed: "false or implicit default", Expected: "readOnlyRootFilesystem: true"},
			"SOC2:CC6", "Kubernetes:Application-Checklist",
		))
	}

	findings = append(findings, imageFindings(workload, container)...)
	return findings
}

func nonRootRisk(pod, container manifest.SecurityContext) (model.Severity, string, bool) {
	if container.RunAsNonRoot != nil {
		if *container.RunAsNonRoot {
			return "", "", false
		}
		return model.SeverityHigh, "container runAsNonRoot: false", true
	}
	if pod.RunAsNonRoot != nil {
		if *pod.RunAsNonRoot {
			return "", "", false
		}
		return model.SeverityHigh, "pod runAsNonRoot: false", true
	}

	user := container.RunAsUser
	if user == nil {
		user = pod.RunAsUser
	}
	if user != nil {
		if *user != 0 {
			return "", "", false
		}
		return model.SeverityHigh, "runAsUser: 0", true
	}
	return model.SeverityMedium, "non-root policy absent", true
}

func seccompRisk(pod, container manifest.SecurityContext) (model.Severity, string, bool) {
	profile := container.SeccompProfile.Type
	if profile == "" {
		profile = pod.SeccompProfile.Type
	}
	switch strings.ToLower(profile) {
	case "runtimedefault", "localhost":
		return "", "", false
	case "unconfined":
		return model.SeverityHigh, "Unconfined", true
	default:
		return model.SeverityMedium, "profile absent", true
	}
}

func unexpectedCapabilities(capabilities []string) []string {
	var unexpected []string
	for _, capability := range capabilities {
		if !strings.EqualFold(capability, "NET_BIND_SERVICE") {
			unexpected = append(unexpected, strings.ToUpper(capability))
		}
	}
	sort.Strings(unexpected)
	return unexpected
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func imageFindings(workload manifest.Workload, container manifest.Container) []model.Finding {
	image := strings.TrimSpace(container.Image)
	if image == "" || strings.Contains(image, "@sha256:") {
		return nil
	}

	var findings []model.Finding
	if imageUsesLatest(image) {
		findings = append(findings, containerFinding(
			workload, container,
			"CP-SUPPLY-001", model.SeverityHigh,
			"Container image uses a mutable latest tag",
			"A mutable tag can resolve to different content without a manifest change or review.",
			"Pin the image to an immutable sha256 digest produced by the trusted build pipeline.",
			model.Evidence{Observed: "latest or implicit tag", Expected: "image@sha256:<digest>"},
			"SOC2:CC7", "SLSA:Provenance",
		))
	}
	findings = append(findings, containerFinding(
		workload, container,
		"CP-SUPPLY-002", model.SeverityMedium,
		"Container image is not digest pinned",
		"Tags are mutable and do not prove which image bytes were reviewed and deployed.",
		"Replace the tag with the verified image digest while retaining the tag in deployment metadata if useful.",
		model.Evidence{Observed: "tag reference", Expected: "sha256 digest reference"},
		"SOC2:CC7", "SLSA:Provenance",
	))
	return findings
}

func imageUsesLatest(image string) bool {
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	return lastColon <= lastSlash || strings.EqualFold(image[lastColon+1:], "latest")
}

func containerFinding(
	workload manifest.Workload,
	container manifest.Container,
	id string,
	severity model.Severity,
	title, description, remediation string,
	evidence model.Evidence,
	controlRefs ...string,
) model.Finding {
	result := finding(workload, id, severity, title, description, remediation, evidence, controlRefs...)
	result.Location.Container = container.Name
	return result
}

func finding(
	workload manifest.Workload,
	id string,
	severity model.Severity,
	title, description, remediation string,
	evidence model.Evidence,
	controlRefs ...string,
) model.Finding {
	return model.Finding{
		ID:          id,
		Severity:    severity,
		Title:       title,
		Description: description,
		Remediation: remediation,
		Source:      "clusterproof",
		Target:      workload.Target(),
		Location:    workload.Location,
		Evidence:    evidence,
		ControlRefs: append([]string(nil), controlRefs...),
		ExternalRefs: map[string]string{
			"guidance": guidanceURL(id),
		},
	}
}

func guidanceURL(id string) string {
	if strings.HasPrefix(id, "CP-SUPPLY-") {
		return "https://slsa.dev/spec/"
	}
	return "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
}
