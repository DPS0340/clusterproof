// Package cluster collects a bounded, read-only snapshot of live Kubernetes workloads.
package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/DPS0340/clusterproof/internal/manifest"
)

const workloadResources = "pods,deployments.apps,statefulsets.apps,daemonsets.apps,replicasets.apps,jobs.batch,cronjobs.batch"

// Options defines the executable, scope, and resource bounds for a cluster scan.
type Options struct {
	Executable     string
	Kubeconfig     string
	Context        string
	Namespace      string
	Timeout        time.Duration
	MaxOutputBytes int64
	MaxErrorBytes  int64
}

// DefaultOptions returns conservative defaults for one live-cluster snapshot.
func DefaultOptions() Options {
	return Options{
		Executable:     "kubectl",
		Timeout:        30 * time.Second,
		MaxOutputBytes: 25 << 20,
		MaxErrorBytes:  64 << 10,
	}
}

// WorkloadArgs returns the fixed read-only kubectl invocation for an option set.
func WorkloadArgs(options Options) []string {
	args := []string{"--kubeconfig", options.Kubeconfig}
	if options.Context != "" {
		args = append(args, "--context", options.Context)
	}
	args = append(args, "get", workloadResources)
	if options.Namespace == "" {
		args = append(args, "--all-namespaces")
	} else {
		args = append(args, "--namespace", options.Namespace)
	}
	return append(args,
		"--output=yaml",
		"--show-managed-fields=false",
		"--request-timeout="+options.Timeout.String(),
	)
}

// Collect invokes kubectl without a shell and normalizes its in-memory YAML snapshot.
func Collect(ctx context.Context, options Options) (manifest.Result, error) {
	if strings.TrimSpace(options.Kubeconfig) == "" {
		return manifest.Result{}, errors.New("kubeconfig path is required")
	}
	if strings.TrimSpace(options.Executable) == "" || options.Timeout <= 0 ||
		options.MaxOutputBytes <= 0 || options.MaxErrorBytes <= 0 {
		return manifest.Result{}, errors.New("invalid cluster collection options")
	}
	if err := validateScope("context", options.Context); err != nil {
		return manifest.Result{}, err
	}
	if err := validateScope("namespace", options.Namespace); err != nil {
		return manifest.Result{}, err
	}

	executable, err := exec.LookPath(options.Executable)
	if err != nil {
		return manifest.Result{}, fmt.Errorf("find kubectl executable: %w", err)
	}
	runContext, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	stdout := newCappedBuffer(options.MaxOutputBytes)
	stderr := newCappedBuffer(options.MaxErrorBytes)
	command := exec.CommandContext(runContext, executable, WorkloadArgs(options)...)
	command.Stdout = stdout
	command.Stderr = stderr

	if err := command.Run(); err != nil {
		if errors.Is(runContext.Err(), context.DeadlineExceeded) {
			return manifest.Result{}, fmt.Errorf("cluster collection exceeded timeout of %s", options.Timeout)
		}
		if errors.Is(runContext.Err(), context.Canceled) {
			return manifest.Result{}, fmt.Errorf("cluster collection canceled: %w", runContext.Err())
		}
		return manifest.Result{}, fmt.Errorf("kubectl get workloads failed: %w: %s", err, cleanText(stderr.String()))
	}
	if stdout.exceeded {
		return manifest.Result{}, fmt.Errorf("kubectl output exceeds limit of %d bytes", options.MaxOutputBytes)
	}
	if stderr.exceeded {
		return manifest.Result{}, fmt.Errorf("kubectl error output exceeds limit of %d bytes", options.MaxErrorBytes)
	}

	result, err := manifest.LoadBytes(
		snapshotSource(options),
		stdout.Bytes(),
		snapshotLimits(options.MaxOutputBytes),
	)
	if err != nil {
		return manifest.Result{}, err
	}
	result.Workloads = topLevelWorkloads(result.Workloads)
	return result, nil
}

func topLevelWorkloads(workloads []manifest.Workload) []manifest.Workload {
	filtered := make([]manifest.Workload, 0, len(workloads))
	for _, workload := range workloads {
		switch workload.Kind {
		case "Pod":
			if hasOwnerKind(workload, "ReplicaSet", "StatefulSet", "DaemonSet", "Job") {
				continue
			}
		case "ReplicaSet":
			if hasOwnerKind(workload, "Deployment") {
				continue
			}
		case "Job":
			if hasOwnerKind(workload, "CronJob") {
				continue
			}
		}
		filtered = append(filtered, workload)
	}
	return filtered
}

func hasOwnerKind(workload manifest.Workload, kinds ...string) bool {
	for _, owner := range workload.OwnerKinds {
		for _, kind := range kinds {
			if owner == kind {
				return true
			}
		}
	}
	return false
}

func snapshotLimits(maxOutputBytes int64) manifest.Limits {
	limits := manifest.DefaultLimits()
	limits.MaxFileBytes = maxOutputBytes
	limits.MaxTotalBytes = maxOutputBytes

	// A kubectl multi-resource List has substantially more nodes than one
	// repository document at the same byte size. Bytes remain the primary memory
	// bound; this prevents the repository-tuned node count from rejecting a valid
	// aggregate snapshot after it has already been decoded.
	nodeBudget := maxOutputBytes / 8
	maxInt := int64(^uint(0) >> 1)
	if nodeBudget > int64(limits.MaxNodes) && nodeBudget <= maxInt {
		limits.MaxNodes = int(nodeBudget)
	}
	return limits
}

func snapshotSource(options Options) string {
	contextName := options.Context
	if contextName == "" {
		contextName = "current-context"
	}
	namespace := options.Namespace
	if namespace == "" {
		namespace = "all-namespaces"
	}
	return "cluster:" + contextName + ":" + namespace
}

func validateScope(name, value string) error {
	for _, current := range value {
		if unicode.IsControl(current) {
			return fmt.Errorf("%s contains control characters", name)
		}
	}
	return nil
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
}

func newCappedBuffer(limit int64) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining > 0 {
		toWrite := data
		if int64(len(toWrite)) > remaining {
			toWrite = toWrite[:remaining]
		}
		_, _ = b.buffer.Write(toWrite)
	}
	if int64(len(data)) > remaining {
		b.exceeded = true
	}
	return len(data), nil
}

func (b *cappedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *cappedBuffer) String() string {
	return b.buffer.String()
}

func cleanText(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, current := range value {
		if builder.Len() >= 1_000 {
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
