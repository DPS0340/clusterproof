package manifest_test

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/rules"
)

// buildLargeSnapshot renders one kubectl-style List with the requested
// number of Deployment workloads, alternating secure and insecure specs.
func buildLargeSnapshot(workloads int) []byte {
	var builder bytes.Buffer
	builder.WriteString("apiVersion: v1\nkind: List\nitems:\n")
	for index := 0; index < workloads; index++ {
		secure := index%2 == 0
		fmt.Fprintf(&builder, `- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: workload-%d
    namespace: namespace-%d
  spec:
    template:
      metadata:
        labels: {app: workload-%d}
      spec:
`, index, index%100, index)
		if secure {
			builder.WriteString(`        automountServiceAccountToken: false
        securityContext:
          runAsNonRoot: true
          seccompProfile: {type: RuntimeDefault}
        containers:
          - name: app
            image: example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            securityContext:
              allowPrivilegeEscalation: false
              runAsNonRoot: true
              readOnlyRootFilesystem: true
              capabilities: {drop: [ALL]}
`)
		} else {
			builder.WriteString(`        hostNetwork: true
        containers:
          - name: app
            image: example.com/app:latest
            securityContext: {privileged: true}
`)
		}
	}
	return builder.Bytes()
}

func snapshotPerformanceLimits(size int) manifest.Limits {
	limits := manifest.DefaultLimits()
	limits.MaxFileBytes = int64(size) + (1 << 20)
	limits.MaxTotalBytes = limits.MaxFileBytes
	limits.MaxNodes = int(limits.MaxFileBytes / 8)
	return limits
}

// TestLargeSnapshotWithinResourceBudget enforces the documented v0.5
// budget: parsing and evaluating a 5,000-workload snapshot must finish
// within 10 seconds and 512 MiB on the test host.
func TestLargeSnapshotWithinResourceBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("performance gate skipped in short mode")
	}
	const workloadCount = 5_000
	data := buildLargeSnapshot(workloadCount)

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()

	result, err := manifest.LoadBytes("performance-fixture", data, snapshotPerformanceLimits(len(data)))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	findings := 0
	for _, workload := range result.Workloads {
		findings += len(rules.Evaluate(workload))
	}

	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if len(result.Workloads) != workloadCount {
		t.Fatalf("workloads = %d, want %d", len(result.Workloads), workloadCount)
	}
	if findings == 0 {
		t.Fatal("insecure fixture workloads produced no findings")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("scan took %s, budget is 10s", elapsed)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	const budget = 512 << 20
	if after.HeapInuse > budget {
		t.Fatalf("heap in use %d bytes exceeds 512 MiB budget", after.HeapInuse)
	}
	t.Logf("%d workloads, %d findings, %s elapsed, %d MiB total allocated, %d MiB heap in use",
		workloadCount, findings, elapsed, allocated>>20, after.HeapInuse>>20)
}

func BenchmarkLoadAndEvaluateLargeSnapshot(b *testing.B) {
	data := buildLargeSnapshot(5_000)
	limits := snapshotPerformanceLimits(len(data))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		result, err := manifest.LoadBytes("benchmark-fixture", data, limits)
		if err != nil {
			b.Fatalf("LoadBytes: %v", err)
		}
		for _, workload := range result.Workloads {
			rules.Evaluate(workload)
		}
	}
}
