package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DPS0340/clusterproof/internal/cluster"
	"github.com/DPS0340/clusterproof/internal/evidence"
	"github.com/DPS0340/clusterproof/internal/exception"
	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
	"github.com/DPS0340/clusterproof/internal/policyreport"
	"github.com/DPS0340/clusterproof/internal/report"
	"github.com/DPS0340/clusterproof/internal/rules"
	"github.com/DPS0340/clusterproof/internal/trivy"
)

var version = "dev"
var kubectlExecutable = "kubectl"

type scanOptions struct {
	target      string
	stdin       bool
	kubeconfig  string
	context     string
	namespace   string
	format      string
	output      string
	evidenceDir string
	failOn      string
	trivyJSON   string
	policyJSON  string
	exceptions  string
	withTrivy   bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "scan":
		return runScan(args[1:], stdin, stdout, stderr)
	case "evidence":
		return runEvidence(args[1:], stdout, stderr)
	case "ruleset":
		return runRuleset(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printExplainUsage(stdout)
		return 0
	}
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "clusterproof: explain requires exactly one RULE_ID")
		printExplainUsage(stderr)
		return 1
	}

	catalog := rules.DefaultCatalog()
	rule, found := catalog.FindRule(args[0])
	if !found {
		fmt.Fprintf(stderr, "clusterproof: unknown rule %q; run \"clusterproof ruleset show\" for the catalog\n", args[0])
		return 1
	}

	osNames := make([]string, 0, len(rule.OS))
	for _, os := range rule.OS {
		osNames = append(osNames, string(os))
	}
	fmt.Fprintf(stdout, "%s: %s\n\n", rule.ID, rule.Title)
	fmt.Fprintf(stdout, "Category:     %s\n", rule.Category)
	fmt.Fprintf(stdout, "Applies to:   %s workloads\n", strings.Join(osNames, " and "))
	fmt.Fprintf(stdout, "Ruleset:      %s %s (Kubernetes %s)\n\n", catalog.ID, catalog.Version, catalog.Kubernetes.KubernetesMinor)
	fmt.Fprintf(stdout, "Why it matters:\n  %s\n\n", rule.Description)
	fmt.Fprintf(stdout, "Remediation:\n  %s\n\n", rule.Remediation)
	fmt.Fprintln(stdout, "Control references:")
	for _, reference := range rule.ControlRefs {
		fmt.Fprintf(stdout, "  - %s\n", reference)
	}
	fmt.Fprintln(stdout, "\nSources:")
	for _, source := range rule.Sources {
		fmt.Fprintf(stdout, "  - %s %s (%s)\n    %s\n", source.Name, source.Version, source.Relationship, source.URL)
	}
	for _, coverage := range catalog.Coverage {
		for _, ruleID := range coverage.RuleIDs {
			if ruleID != rule.ID {
				continue
			}
			fmt.Fprintf(stdout, "\nPSS coverage: %s / %s (%s)\n", coverage.Profile, coverage.Control, coverage.Status)
			if coverage.Note != "" {
				fmt.Fprintf(stdout, "  Note: %s\n", coverage.Note)
			}
		}
	}
	return 0
}

func printExplainUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  clusterproof explain RULE_ID

Shows the source, scope, rationale, and remediation for one native rule.`)
}

func runEvidence(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printEvidenceUsage(stdout)
		return 0
	}
	if len(args) != 2 || args[0] != "verify" {
		fmt.Fprintln(stderr, "clusterproof: evidence requires: verify DIR")
		printEvidenceUsage(stderr)
		return 1
	}
	if err := evidence.VerifyBundle(args[1]); err != nil {
		fmt.Fprintf(stderr, "clusterproof: verify evidence: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "evidence bundle verified")
	return 0
}

func runRuleset(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printRulesetUsage(stdout)
		return 0
	}
	if len(args) == 0 || args[0] != "show" {
		fmt.Fprintln(stderr, "clusterproof: ruleset requires: show")
		printRulesetUsage(stderr)
		return 1
	}
	format := "table"
	for index := 1; index < len(args); index++ {
		current := args[index]
		switch {
		case current == "-h" || current == "--help":
			printRulesetUsage(stdout)
			return 0
		case current == "--format":
			if index+1 >= len(args) {
				fmt.Fprintln(stderr, "clusterproof: --format requires a value")
				return 1
			}
			format = args[index+1]
			index++
		case strings.HasPrefix(current, "--format="):
			format = strings.TrimPrefix(current, "--format=")
		default:
			fmt.Fprintf(stderr, "clusterproof: unknown ruleset argument %q\n", current)
			return 1
		}
	}

	catalog := rules.DefaultCatalog()
	switch format {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(catalog); err != nil {
			fmt.Fprintf(stderr, "clusterproof: write ruleset JSON: %v\n", err)
			return 1
		}
	case "table":
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintf(
			writer,
			"RULESET\tVERSION\tKUBERNETES\tSUPPORTED MINORS\tRULES\n%s\t%s\t%s\t%s\t%d\n\n",
			catalog.ID,
			catalog.Version,
			catalog.Kubernetes.KubernetesMinor,
			strings.Join(catalog.Kubernetes.SupportedMinors, ", "),
			len(catalog.Rules),
		)
		fmt.Fprintln(writer, "RULE\tCATEGORY\tOS\tSOURCE")
		for _, rule := range catalog.Rules {
			sources := make([]string, 0, len(rule.Sources))
			for _, source := range rule.Sources {
				sources = append(sources, source.Name+" "+source.Version)
			}
			osNames := make([]string, 0, len(rule.OS))
			for _, os := range rule.OS {
				osNames = append(osNames, string(os))
			}
			fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", rule.ID, rule.Category, strings.Join(osNames, ", "), strings.Join(sources, ", "))
		}
		if err := writer.Flush(); err != nil {
			fmt.Fprintf(stderr, "clusterproof: write ruleset table: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintln(stderr, "clusterproof: ruleset format must be table or json")
		return 1
	}
	return 0
}

func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	options, help, err := parseScanOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "clusterproof: %v\n", err)
		return 1
	}
	if help {
		printScanUsage(stdout)
		return 0
	}

	var loaded manifest.Result
	scanTarget := options.target
	switch {
	case options.stdin:
		limits := manifest.DefaultLimits()
		data, readErr := io.ReadAll(io.LimitReader(stdin, limits.MaxFileBytes+1))
		if readErr != nil {
			fmt.Fprintf(stderr, "clusterproof: read stdin: %v\n", readErr)
			return 1
		}
		if int64(len(data)) > limits.MaxFileBytes {
			fmt.Fprintf(stderr, "clusterproof: stdin exceeds limit of %d bytes\n", limits.MaxFileBytes)
			return 1
		}
		if len(bytes.TrimSpace(data)) == 0 {
			fmt.Fprintln(stderr, "clusterproof: stdin is empty; pipe rendered YAML or JSON manifests")
			return 1
		}
		loaded, err = manifest.LoadBytes("stdin", data, limits)
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: load stdin manifests: %v\n", err)
			return 1
		}
		scanTarget = "stdin"
	case options.kubeconfig != "":
		clusterOptions := cluster.DefaultOptions()
		clusterOptions.Executable = kubectlExecutable
		clusterOptions.Kubeconfig = options.kubeconfig
		clusterOptions.Context = options.context
		clusterOptions.Namespace = options.namespace
		loaded, err = cluster.Collect(context.Background(), clusterOptions)
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: collect cluster: %v\n", err)
			return 1
		}
		scanTarget = loaded.Inputs[0].Path
	default:
		loaded, err = manifest.Load(options.target, manifest.DefaultLimits())
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: load manifests: %v\n", err)
			return 1
		}
	}
	var findings []model.Finding
	for _, workload := range loaded.Workloads {
		findings = append(findings, rules.Evaluate(workload)...)
	}

	if options.policyJSON != "" {
		imported, err := policyreport.Load(options.policyJSON, policyreport.DefaultLimits())
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: import PolicyReport JSON: %v\n", err)
			return 1
		}
		findings = append(findings, imported.Findings...)
		loaded.Inputs = append(loaded.Inputs, imported.Input)
	}

	if options.trivyJSON != "" {
		file, err := os.Open(options.trivyJSON)
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: open Trivy JSON: %v\n", err)
			return 1
		}
		enriched, parseErr := trivy.Parse(file, 100<<20)
		closeErr := file.Close()
		if parseErr != nil {
			fmt.Fprintf(stderr, "clusterproof: import Trivy JSON: %v\n", parseErr)
			return 1
		}
		if closeErr != nil {
			fmt.Fprintf(stderr, "clusterproof: close Trivy JSON: %v\n", closeErr)
			return 1
		}
		findings = append(findings, enriched...)
	}
	if options.withTrivy {
		enriched, err := trivy.RunFilesystem(context.Background(), options.target, trivy.DefaultRunOptions())
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: run Trivy: %v\n", err)
			return 1
		}
		findings = append(findings, enriched...)
	}
	sortFindings(findings)

	var suppressed []model.SuppressedFinding
	if options.exceptions != "" {
		entries, loadErr := exception.Load(options.exceptions, exception.DefaultLimits())
		if loadErr != nil {
			fmt.Fprintf(stderr, "clusterproof: load exceptions: %v\n", loadErr)
			return 1
		}
		findings, suppressed = exception.Apply(findings, entries, time.Now().UTC())
	}

	rulesetReference := rules.DefaultCatalog().Reference()
	assessmentStatus := model.AssessmentStatusAssessed
	if len(loaded.Workloads) == 0 {
		assessmentStatus = model.AssessmentStatusNoWorkloads
	}
	assessment := model.Assessment{
		Status:            assessmentStatus,
		InputsScanned:     len(loaded.Inputs),
		WorkloadsAssessed: len(loaded.Workloads),
	}
	scan := model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC(),
		Target:        scanTarget,
		ToolVersion:   version,
		Ruleset:       &rulesetReference,
		Assessment:    &assessment,
		Inputs:        loaded.Inputs,
		Findings:      findings,
		Suppressed:    suppressed,
		Summary:       model.Summarize(findings),
	}
	if options.evidenceDir != "" {
		if err := evidence.WriteBundle(options.evidenceDir, scan); err != nil {
			fmt.Fprintf(stderr, "clusterproof: write evidence: %v\n", err)
			return 1
		}
	}

	var rendered bytes.Buffer
	switch options.format {
	case "table":
		err = report.Table(&rendered, scan)
	case "json":
		err = report.JSON(&rendered, scan)
	case "sarif":
		err = report.SARIF(&rendered, scan)
	default:
		err = fmt.Errorf("unsupported format %q", options.format)
	}
	if err != nil {
		fmt.Fprintf(stderr, "clusterproof: render report: %v\n", err)
		return 1
	}
	if options.output == "" {
		if _, err := io.Copy(stdout, &rendered); err != nil {
			fmt.Fprintf(stderr, "clusterproof: write report: %v\n", err)
			return 1
		}
	} else if err := report.WriteNew(options.output, rendered.Bytes()); err != nil {
		fmt.Fprintf(stderr, "clusterproof: write report: %v\n", err)
		return 1
	}

	if options.failOn != "" {
		threshold, err := model.ParseSeverity(options.failOn)
		if err != nil {
			fmt.Fprintf(stderr, "clusterproof: %v\n", err)
			return 1
		}
		for _, finding := range findings {
			if finding.Severity.Meets(threshold) {
				return 2
			}
		}
	}
	return 0
}

func parseScanOptions(args []string) (scanOptions, bool, error) {
	options := scanOptions{format: "table"}
	valueFlags := map[string]*string{
		"--format":             &options.format,
		"--output":             &options.output,
		"--evidence-dir":       &options.evidenceDir,
		"--fail-on":            &options.failOn,
		"--trivy-json":         &options.trivyJSON,
		"--policy-report-json": &options.policyJSON,
		"--exceptions":         &options.exceptions,
		"--kubeconfig":         &options.kubeconfig,
		"--context":            &options.context,
		"--namespace":          &options.namespace,
	}

	for index := 0; index < len(args); index++ {
		current := args[index]
		if current == "-h" || current == "--help" {
			return options, true, nil
		}
		if current == "--with-trivy" {
			options.withTrivy = true
			continue
		}
		if current == "--" {
			if index+1 >= len(args) || options.target != "" {
				return options, false, fmt.Errorf("-- must be followed by one scan path")
			}
			options.target = args[index+1]
			index++
			continue
		}
		if current == "-" {
			if options.stdin {
				return options, false, fmt.Errorf("stdin target - is accepted only once")
			}
			options.stdin = true
			continue
		}

		matched := false
		for name, destination := range valueFlags {
			if current == name {
				if index+1 >= len(args) {
					return options, false, fmt.Errorf("%s requires a value", name)
				}
				*destination = args[index+1]
				index++
				matched = true
				break
			}
			if strings.HasPrefix(current, name+"=") {
				*destination = strings.TrimPrefix(current, name+"=")
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if strings.HasPrefix(current, "-") {
			return options, false, fmt.Errorf("unknown flag %q", current)
		}
		if options.target != "" {
			return options, false, fmt.Errorf("only one scan path is accepted")
		}
		options.target = current
	}

	targets := 0
	if options.target != "" {
		targets++
	}
	if options.kubeconfig != "" {
		targets++
	}
	if options.stdin {
		targets++
	}
	if targets == 0 {
		return options, false, fmt.Errorf("scan path, -, or --kubeconfig is required")
	}
	if targets > 1 {
		return options, false, fmt.Errorf("scan path, -, and --kubeconfig are mutually exclusive")
	}
	if options.kubeconfig == "" && (options.context != "" || options.namespace != "") {
		return options, false, fmt.Errorf("--context and --namespace require --kubeconfig")
	}
	if options.kubeconfig != "" && (options.withTrivy || options.trivyJSON != "") {
		return options, false, fmt.Errorf("trivy options are only supported for repository scans")
	}
	if options.stdin && options.withTrivy {
		return options, false, fmt.Errorf("--with-trivy requires a repository path")
	}
	if options.trivyJSON != "" && options.withTrivy {
		return options, false, fmt.Errorf("--trivy-json and --with-trivy cannot be combined")
	}
	switch options.format {
	case "table", "json", "sarif":
	default:
		return options, false, fmt.Errorf("format must be table, json, or sarif")
	}
	if options.failOn != "" {
		if _, err := model.ParseSeverity(options.failOn); err != nil {
			return options, false, err
		}
	}
	return options, false, nil
}

func sortFindings(findings []model.Finding) {
	rank := map[model.Severity]int{
		model.SeverityInfo: 0, model.SeverityLow: 1, model.SeverityMedium: 2,
		model.SeverityHigh: 3, model.SeverityCritical: 4,
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return rank[findings[i].Severity] > rank[findings[j].Severity]
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].Location.Container < findings[j].Location.Container
	})
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `ClusterProof scans Kubernetes manifests and produces security evidence.

Usage:
  kubectl clusterproof scan [flags] PATH
  kubectl clusterproof scan [flags] --kubeconfig PATH
  clusterproof scan [flags] PATH
  clusterproof scan [flags] --kubeconfig PATH
  clusterproof evidence verify DIR
  clusterproof ruleset show [--format table|json]
  clusterproof explain RULE_ID
  clusterproof version

Run "clusterproof scan --help" for scan flags.`)
}

func printScanUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  kubectl clusterproof scan [flags] PATH
  kubectl clusterproof scan [flags] -
  kubectl clusterproof scan [flags] --kubeconfig PATH

Flags:
  --format table|json|sarif  Output format (default table)
  --output PATH              Create report file; refuses overwrite
  --evidence-dir PATH        Create integrity-checked readiness evidence
  --fail-on SEVERITY         Exit 2 for findings at or above severity
  --trivy-json PATH          Import existing Trivy JSON
  --policy-report-json PATH  Import wgpolicyk8s PolicyReport JSON results
  --exceptions PATH          Apply a reviewed repository exception file
  --with-trivy               Explicitly run local Trivy (may update its databases)
  --kubeconfig PATH          Read workloads from the selected cluster
  --context NAME             Kubeconfig context (default current context)
  --namespace NAME           Scan one namespace (default all namespaces)
  -h, --help                 Show help

Use - to read bounded multi-document YAML or JSON from stdin, for example:
  helm template ./chart | clusterproof scan -
ClusterProof never executes a renderer; pipe already-rendered manifests.`)
}

func printEvidenceUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  clusterproof evidence verify DIR

Verifies the exact file set, byte sizes, and SHA-256 hashes in an evidence bundle.`)
}

func printRulesetUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  clusterproof ruleset show [--format table|json]

Shows the exact versioned native rule catalog and its official sources.`)
}
