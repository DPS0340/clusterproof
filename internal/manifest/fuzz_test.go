package manifest

import "testing"

// FuzzLoadBytes proves hostile YAML can never panic or bypass limits; any
// outcome other than a clean error or a bounded result is a bug.
func FuzzLoadBytes(f *testing.F) {
	f.Add([]byte("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: a, image: i}]}\n"))
	f.Add([]byte("apiVersion: v1\nkind: List\nitems: [{kind: Namespace, metadata: {name: n}}]\n"))
	f.Add([]byte("{"))
	f.Add([]byte("&a [*a]"))
	f.Add([]byte("kind: NetworkPolicy\nspec: {podSelector: {}}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := DefaultLimits()
		limits.MaxFileBytes = 1 << 20
		limits.MaxTotalBytes = 1 << 20
		result, err := LoadBytes("fuzz", data, limits)
		if err != nil {
			return
		}
		if len(result.Workloads) > limits.MaxDocuments {
			t.Fatalf("workload count %d escaped document limit", len(result.Workloads))
		}
	})
}
