// Package manifest safely loads local Kubernetes YAML into normalized workloads.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/model"
	"gopkg.in/yaml.v3"
)

// Limits bounds work performed on untrusted manifest input.
type Limits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxDocuments  int
	MaxNodes      int
	MaxDepth      int
}

// DefaultLimits returns conservative limits suitable for a repository scan.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:      2_000,
		MaxFileBytes:  5 << 20,
		MaxTotalBytes: 100 << 20,
		MaxDocuments:  10_000,
		MaxNodes:      200_000,
		MaxDepth:      64,
	}
}

// Load discovers bounded YAML input without following symlinks.
func Load(root string, limits Limits) (Result, error) {
	if err := validateLimits(limits); err != nil {
		return Result{}, err
	}
	paths, err := discover(root, limits.MaxFiles)
	if err != nil {
		return Result{}, err
	}

	var result Result
	var totalBytes int64
	documents := 0
	for _, path := range paths {
		data, err := readBounded(path, limits.MaxFileBytes)
		if err != nil {
			return Result{}, err
		}
		totalBytes += int64(len(data))
		if totalBytes > limits.MaxTotalBytes {
			return Result{}, fmt.Errorf("manifest input exceeds total limit of %d bytes", limits.MaxTotalBytes)
		}

		sum := sha256.Sum256(data)
		result.Inputs = append(result.Inputs, model.Input{
			Path:   path,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(data)),
		})

		workloads, namespaces, count, err := decodeFileFull(path, data, documents, limits)
		if err != nil {
			return Result{}, err
		}
		documents += count
		result.Workloads = append(result.Workloads, workloads...)
		result.Namespaces = append(result.Namespaces, namespaces...)
	}
	return result, nil
}

// LoadBytes parses one bounded Kubernetes YAML snapshot without persisting it.
func LoadBytes(source string, data []byte, limits Limits) (Result, error) {
	if strings.TrimSpace(source) == "" {
		return Result{}, errors.New("manifest source is required")
	}
	if err := validateLimits(limits); err != nil {
		return Result{}, err
	}
	if int64(len(data)) > limits.MaxFileBytes {
		return Result{}, fmt.Errorf("manifest %q exceeds file limit of %d bytes", source, limits.MaxFileBytes)
	}
	if int64(len(data)) > limits.MaxTotalBytes {
		return Result{}, fmt.Errorf("manifest input exceeds total limit of %d bytes", limits.MaxTotalBytes)
	}

	sum := sha256.Sum256(data)
	var parsed parsedObjects
	if _, err := decodeAll(&parsed, source, data, 0, limits); err != nil {
		return Result{}, err
	}
	return Result{
		Inputs: []model.Input{{
			Path:   source,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(data)),
		}},
		Workloads:       parsed.workloads,
		Namespaces:      parsed.namespaces,
		RBACRoles:       parsed.roles,
		RBACBindings:    parsed.bindings,
		NetworkPolicies: parsed.policies,
		Services:        parsed.services,
	}, nil
}

func validateLimits(limits Limits) error {
	if limits.MaxFiles <= 0 || limits.MaxFileBytes <= 0 || limits.MaxTotalBytes <= 0 ||
		limits.MaxDocuments <= 0 || limits.MaxNodes <= 0 || limits.MaxDepth <= 0 {
		return errors.New("all manifest limits must be positive")
	}
	return nil
}

func discover(root string, maxFiles int) ([]string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect scan path %q: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("scan path %q is a symlink", root)
	}
	if info.Mode().IsRegular() {
		if !isYAML(root) {
			return nil, fmt.Errorf("scan file %q is not YAML", root)
		}
		return []string{root}, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan path %q is not a regular file or directory", root)
	}

	var paths []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %q: %w", path, walkErr)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() || !isYAML(path) {
			return nil
		}
		paths = append(paths, path)
		if len(paths) > maxFiles {
			return fmt.Errorf("manifest input exceeds file limit of %d", maxFiles)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func isYAML(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yaml" || extension == ".yml"
}

func readBounded(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest %q: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", path, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("manifest %q exceeds file limit of %d bytes", path, maxBytes)
	}
	return data, nil
}

func decodeFileFull(path string, data []byte, priorDocuments int, limits Limits) ([]Workload, []Namespace, int, error) {
	var parsed parsedObjects
	count, err := decodeAll(&parsed, path, data, priorDocuments, limits)
	return parsed.workloads, parsed.namespaces, count, err
}

// parsedObjects accumulates every normalized object kind from one input.
type parsedObjects struct {
	workloads  []Workload
	namespaces []Namespace
	roles      []RBACRole
	bindings   []RBACBinding
	policies   []NetworkPolicy
	services   []Service
}

func decodeAll(parsed *parsedObjects, path string, data []byte, priorDocuments int, limits Limits) (int, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	documents := 0

	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return documents, fmt.Errorf("decode manifest %q document %d: %w", path, documents+1, err)
		}
		if len(document.Content) == 0 {
			continue
		}
		documents++
		if priorDocuments+documents > limits.MaxDocuments {
			return documents, fmt.Errorf("manifest input exceeds document limit of %d", limits.MaxDocuments)
		}
		if err := validateNode(&document, limits); err != nil {
			return documents, fmt.Errorf("validate manifest %q document %d: %w", path, documents, err)
		}

		var resource rawResource
		if err := document.Decode(&resource); err != nil {
			return documents, fmt.Errorf("normalize manifest %q document %d: %w", path, documents, err)
		}
		normalizeInto(parsed, resource, path, documents, document.Content[0].Line)
	}
	return documents, nil
}

func normalizeInto(parsed *parsedObjects, resource rawResource, path string, document, line int) {
	if resource.Kind == "List" {
		for _, item := range resource.Items {
			normalizeInto(parsed, item, path, document, line)
		}
		return
	}

	location := model.Location{
		Path:     path,
		Document: document,
		Line:     line,
		Resource: resource.Kind + "/" + resource.Metadata.Name,
	}

	if resource.Kind == "Namespace" {
		labels := make(map[string]string, len(resource.Metadata.Labels))
		for key, value := range resource.Metadata.Labels {
			labels[key] = value
		}
		parsed.namespaces = append(parsed.namespaces, Namespace{
			Name:     resource.Metadata.Name,
			Labels:   labels,
			Location: location,
		})
		return
	}

	if resource.Kind == "Role" || resource.Kind == "ClusterRole" {
		parsed.roles = append(parsed.roles, RBACRole{
			Kind:       resource.Kind,
			Namespace:  resource.Metadata.Namespace,
			Name:       resource.Metadata.Name,
			Rules:      normalizeRBACRules(resource.Rules),
			Aggregates: len(resource.AggregationRule.ClusterRoleSelectors) > 0,
			Location:   location,
		})
		return
	}

	if resource.Kind == "RoleBinding" || resource.Kind == "ClusterRoleBinding" {
		subjects := make([]RBACSubject, 0, len(resource.Subjects))
		for _, subject := range resource.Subjects {
			subjects = append(subjects, RBACSubject{
				Kind:      subject.Kind,
				Namespace: subject.Namespace,
				Name:      subject.Name,
			})
		}
		parsed.bindings = append(parsed.bindings, RBACBinding{
			Kind:      resource.Kind,
			Namespace: resource.Metadata.Namespace,
			Name:      resource.Metadata.Name,
			RoleKind:  resource.RoleRef.Kind,
			RoleName:  resource.RoleRef.Name,
			Subjects:  subjects,
			Location:  location,
		})
		return
	}

	if resource.Kind == "NetworkPolicy" {
		policyTypes := append([]string(nil), resource.Spec.PolicyTypes...)
		parsed.policies = append(parsed.policies, NetworkPolicy{
			Namespace:         resource.Metadata.Namespace,
			Name:              resource.Metadata.Name,
			SelectsAllPods:    len(resource.Spec.PodSelector.MatchLabels) == 0 && len(resource.Spec.PodSelector.MatchExpressions) == 0,
			PodSelectorLabels: copyLabels(resource.Spec.PodSelector.MatchLabels),
			PolicyTypes:       policyTypes,
			HasIngressRules:   len(resource.Spec.Ingress) > 0,
			HasEgressRules:    len(resource.Spec.Egress) > 0,
			Location:          location,
		})
		return
	}

	if resource.Kind == "Service" {
		serviceType := resource.Spec.Type
		if serviceType == "" {
			serviceType = "ClusterIP"
		}
		parsed.services = append(parsed.services, Service{
			Namespace: resource.Metadata.Namespace,
			Name:      resource.Metadata.Name,
			Type:      serviceType,
			Selector:  copyLabels(resource.Spec.Selector),
			Location:  location,
		})
		return
	}

	podSpec, ok := resource.podSpec()
	if !ok {
		return
	}
	parsed.workloads = append(parsed.workloads, Workload{
		APIVersion: resource.APIVersion,
		Kind:       resource.Kind,
		Namespace:  resource.Metadata.Namespace,
		Name:       resource.Metadata.Name,
		OwnerKinds: ownerKinds(resource.Metadata.OwnerReferences),
		PodLabels:  resource.podLabels(),
		Location:   location,
		PodSpec:    podSpec,
	})
}

func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

func normalizeRBACRules(rules []rawPolicyRule) []RBACRule {
	normalized := make([]RBACRule, 0, len(rules))
	for _, rule := range rules {
		normalized = append(normalized, RBACRule{
			APIGroups: append([]string(nil), rule.APIGroups...),
			Resources: append([]string(nil), rule.Resources...),
			Verbs:     append([]string(nil), rule.Verbs...),
		})
	}
	return normalized
}

func ownerKinds(references []rawOwnerReference) []string {
	kinds := make([]string, 0, len(references))
	for _, reference := range references {
		if reference.Kind != "" {
			kinds = append(kinds, reference.Kind)
		}
	}
	return kinds
}

func validateNode(root *yaml.Node, limits Limits) error {
	type item struct {
		node  *yaml.Node
		depth int
	}
	stack := []item{{node: root, depth: 1}}
	nodes := 0

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > limits.MaxNodes {
			return fmt.Errorf("YAML node limit of %d exceeded", limits.MaxNodes)
		}
		if current.depth > limits.MaxDepth {
			return fmt.Errorf("YAML depth limit of %d exceeded", limits.MaxDepth)
		}
		if current.node.Kind == yaml.AliasNode {
			return errors.New("YAML aliases are not accepted")
		}
		for _, child := range current.node.Content {
			stack = append(stack, item{node: child, depth: current.depth + 1})
		}
	}
	return nil
}

type rawResource struct {
	APIVersion      string             `yaml:"apiVersion"`
	Kind            string             `yaml:"kind"`
	Metadata        rawMetadata        `yaml:"metadata"`
	Spec            rawSpec            `yaml:"spec"`
	Items           []rawResource      `yaml:"items"`
	Rules           []rawPolicyRule    `yaml:"rules"`
	Subjects        []rawSubject       `yaml:"subjects"`
	RoleRef         rawRoleRef         `yaml:"roleRef"`
	AggregationRule rawAggregationRule `yaml:"aggregationRule"`
}

type rawPolicyRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

type rawSubject struct {
	Kind      string `yaml:"kind"`
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

type rawRoleRef struct {
	Kind string `yaml:"kind"`
	Name string `yaml:"name"`
}

type rawAggregationRule struct {
	ClusterRoleSelectors []map[string]any `yaml:"clusterRoleSelectors"`
}

type rawMetadata struct {
	Name            string              `yaml:"name"`
	Namespace       string              `yaml:"namespace"`
	Labels          map[string]string   `yaml:"labels"`
	OwnerReferences []rawOwnerReference `yaml:"ownerReferences"`
}

type rawOwnerReference struct {
	Kind string `yaml:"kind"`
}

type rawSpec struct {
	PodSpec     `yaml:",inline"`
	Template    rawTemplate    `yaml:"template"`
	JobTemplate rawJobTemplate `yaml:"jobTemplate"`
	// Network fields for NetworkPolicy and Service normalization.
	PodSelector rawSelector       `yaml:"podSelector"`
	PolicyTypes []string          `yaml:"policyTypes"`
	Ingress     []map[string]any  `yaml:"ingress"`
	Egress      []map[string]any  `yaml:"egress"`
	Type        string            `yaml:"type"`
	Selector    map[string]string `yaml:"selector"`
}

type rawTemplate struct {
	Metadata rawTemplateMetadata `yaml:"metadata"`
	Spec     PodSpec             `yaml:"spec"`
}

type rawTemplateMetadata struct {
	Labels map[string]string `yaml:"labels"`
}

type rawSelector struct {
	MatchLabels      map[string]string `yaml:"matchLabels"`
	MatchExpressions []map[string]any  `yaml:"matchExpressions"`
}

type rawJobTemplate struct {
	Spec struct {
		Template rawTemplate `yaml:"template"`
	} `yaml:"spec"`
}

func (r rawResource) podSpec() (PodSpec, bool) {
	switch r.Kind {
	case "Pod":
		return r.Spec.PodSpec, true
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		return r.Spec.Template.Spec, true
	case "CronJob":
		return r.Spec.JobTemplate.Spec.Template.Spec, true
	default:
		return PodSpec{}, false
	}
}

// podLabels returns the labels used for NetworkPolicy and Service selector
// matching: pod labels for a Pod, template labels for controllers.
func (r rawResource) podLabels() map[string]string {
	switch r.Kind {
	case "Pod":
		return copyLabels(r.Metadata.Labels)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		return copyLabels(r.Spec.Template.Metadata.Labels)
	case "CronJob":
		return copyLabels(r.Spec.JobTemplate.Spec.Template.Metadata.Labels)
	default:
		return nil
	}
}
