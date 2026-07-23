package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kitae1645/clusterproof/internal/evidence"
	"github.com/kitae1645/clusterproof/internal/manifest"
	"github.com/kitae1645/clusterproof/internal/model"
	"github.com/kitae1645/clusterproof/internal/report"
	"github.com/kitae1645/clusterproof/internal/rules"
	"github.com/kitae1645/clusterproof/internal/trivy"
)

var version = "dev"

type scanOptions struct {
	target      string
	format      string
	output      string
	evidenceDir string
	failOn      string
	trivyJSON   string
	withTrivy   bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
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
		return runScan(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	options, help, err := parseScanOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "clusterproof: %v\n", err)
		return 1
	}
	if help {
		printScanUsage(stdout)
		return 0
	}

	loaded, err := manifest.Load(options.target, manifest.DefaultLimits())
	if err != nil {
		fmt.Fprintf(stderr, "clusterproof: load manifests: %v\n", err)
		return 1
	}
	var findings []model.Finding
	for _, workload := range loaded.Workloads {
		findings = append(findings, rules.Evaluate(workload)...)
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

	scan := model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC(),
		Target:        options.target,
		ToolVersion:   version,
		Inputs:        loaded.Inputs,
		Findings:      findings,
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
		"--format":       &options.format,
		"--output":       &options.output,
		"--evidence-dir": &options.evidenceDir,
		"--fail-on":      &options.failOn,
		"--trivy-json":   &options.trivyJSON,
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

	if options.target == "" {
		return options, false, fmt.Errorf("scan path is required")
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
  clusterproof scan [flags] PATH
  clusterproof version

Run "clusterproof scan --help" for scan flags.`)
}

func printScanUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Usage:
  kubectl clusterproof scan [flags] PATH

Flags:
  --format table|json|sarif  Output format (default table)
  --output PATH              Create report file; refuses overwrite
  --evidence-dir PATH        Create immutable readiness evidence bundle
  --fail-on SEVERITY         Exit 2 for findings at or above severity
  --trivy-json PATH          Import existing Trivy JSON
  --with-trivy               Explicitly run local Trivy (may update its databases)
  -h, --help                 Show help`)
}
