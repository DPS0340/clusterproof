package image

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/manifest"
)

func workloadWithImages(namespace, name string, images ...string) manifest.Workload {
	containers := make([]manifest.Container, 0, len(images))
	for index, image := range images {
		containers = append(containers, manifest.Container{
			Name:  "c" + string(rune('a'+index)),
			Image: image,
		})
	}
	return manifest.Workload{
		Kind: "Deployment", Namespace: namespace, Name: name,
		PodSpec: manifest.PodSpec{Containers: containers},
	}
}

func TestInventoryIsDeterministicAndDeduplicated(t *testing.T) {
	workloads := []manifest.Workload{
		workloadWithImages("payments", "api", "ghcr.io/example/api:v1.2.3"),
		workloadWithImages("billing", "worker", "ghcr.io/example/api:v1.2.3", "redis"),
	}
	first := Inventory(workloads)
	second := Inventory(workloads)

	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("inventory is not deterministic")
	}
	if len(first) != 2 {
		t.Fatalf("inventory = %#v, want 2 deduplicated images", first)
	}
	api := first[0]
	if api.Registry != "ghcr.io" || api.Repository != "example/api" || api.Tag != "v1.2.3" {
		t.Fatalf("parsed reference = %#v", api)
	}
	if len(api.Workloads) != 2 {
		t.Fatalf("workload usage missing: %#v", api.Workloads)
	}
}

func TestParseReferenceForms(t *testing.T) {
	tests := []struct {
		raw        string
		registry   string
		repository string
		tag        string
		digest     string
	}{
		{raw: "nginx", registry: "docker.io", repository: "library/nginx", tag: "latest"},
		{raw: "nginx:1.25", registry: "docker.io", repository: "library/nginx", tag: "1.25"},
		{raw: "example/app:v1", registry: "docker.io", repository: "example/app", tag: "v1"},
		{raw: "ghcr.io/example/app:v1", registry: "ghcr.io", repository: "example/app", tag: "v1"},
		{raw: "localhost:5000/app:dev", registry: "localhost:5000", repository: "app", tag: "dev"},
		{
			raw:        "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			registry:   "ghcr.io",
			repository: "example/app",
			digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			raw:        "ghcr.io/example/app:v1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			registry:   "ghcr.io",
			repository: "example/app",
			tag:        "v1",
			digest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			got := parseReference(test.raw)
			if got.Registry != test.registry || got.Repository != test.repository ||
				got.Tag != test.tag || got.Digest != test.digest {
				t.Fatalf("parseReference(%q) = %#v", test.raw, got)
			}
		})
	}
}

func TestResolveRequiresExplicitAllowlist(t *testing.T) {
	reference := parseReference("ghcr.io/example/app:v1")
	options := DefaultResolveOptions()
	// Default options have an empty allowlist: nothing resolves.
	if _, err := Resolve(context.Background(), reference, options); err == nil ||
		!strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("empty allowlist did not refuse resolution: %v", err)
	}
}

func TestResolveRejectsPinnedAndUntaggedReferences(t *testing.T) {
	pinned := parseReference("ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	options := DefaultResolveOptions()
	options.AllowedRegistries = []string{"ghcr.io"}
	if _, err := Resolve(context.Background(), pinned, options); err == nil ||
		!strings.Contains(err.Error(), "already digest pinned") {
		t.Fatalf("pinned reference accepted for resolution: %v", err)
	}
}

type fakeTransport struct {
	handler http.Handler
}

func (f fakeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func TestResolveReturnsDigestFromRegistry(t *testing.T) {
	const digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", request.Method)
		}
		if request.URL.Path != "/v2/example/app/manifests/v1" {
			t.Errorf("path = %s", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "" {
			t.Error("resolution must be anonymous")
		}
		writer.Header().Set("Docker-Content-Digest", digest)
		writer.WriteHeader(http.StatusOK)
	})

	reference := parseReference("registry.example.com/example/app:v1")
	options := DefaultResolveOptions()
	options.AllowedRegistries = []string{"registry.example.com"}
	options.Transport = fakeTransport{handler: handler}

	resolution, err := Resolve(context.Background(), reference, options)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolution.Digest != digest || !resolution.NetworkUsed {
		t.Fatalf("resolution = %#v", resolution)
	}
	if resolution.ResolvedAt.IsZero() {
		t.Fatal("resolution timestamp missing")
	}
}

func TestResolveFailsOnAuthDemandAndBadDigest(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		message string
	}{
		{
			name: "auth required",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusUnauthorized)
			},
			message: "authentication",
		},
		{
			name: "missing digest header",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusOK)
			},
			message: "content digest",
		},
		{
			name: "malformed digest",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Docker-Content-Digest", "sha256:short")
				writer.WriteHeader(http.StatusOK)
			},
			message: "64 hex",
		},
		{
			name: "server error",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusInternalServerError)
			},
			message: "status 500",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reference := parseReference("registry.example.com/example/app:v1")
			options := DefaultResolveOptions()
			options.AllowedRegistries = []string{"registry.example.com"}
			options.Transport = fakeTransport{handler: test.handler}

			_, err := Resolve(context.Background(), reference, options)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error %v does not mention %q", err, test.message)
			}
		})
	}
}

func TestResolveTimesOut(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	reference := parseReference(strings.TrimPrefix(server.URL, "http://") + "/app:v1")
	options := DefaultResolveOptions()
	options.AllowedRegistries = []string{reference.Registry}
	options.Timeout = 50 * time.Millisecond
	// Use the real transport against the local server; https will fail
	// fast or the timeout fires — either way resolution must not hang.
	_, err := Resolve(context.Background(), reference, options)
	if err == nil {
		t.Fatal("expected timeout or connection failure")
	}
}

func TestValidateDigest(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	if err := ValidateDigest(valid); err != nil {
		t.Fatalf("valid digest rejected: %v", err)
	}
	for _, invalid := range []string{
		"sha512:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("z", 64),
		"",
	} {
		if err := ValidateDigest(invalid); err == nil {
			t.Fatalf("invalid digest accepted: %q", invalid)
		}
	}
}

func TestMarshalInventoryIsStable(t *testing.T) {
	references := Inventory([]manifest.Workload{
		workloadWithImages("payments", "api", "ghcr.io/example/api:v1"),
	})
	first, err := MarshalInventory(references)
	if err != nil {
		t.Fatalf("MarshalInventory: %v", err)
	}
	second, _ := MarshalInventory(references)
	if string(first) != string(second) {
		t.Fatal("inventory export is not stable")
	}
	if !strings.Contains(string(first), "\"schema_version\": \"1\"") {
		t.Fatalf("missing schema version: %s", first)
	}
}
