package arsenal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeTargetVariants(t *testing.T) {
	cases := []struct {
		raw      string
		domain   string
		rootURL  string
		isLocal  bool
	}{
		{"ahsanli.com", "ahsanli.com", "https://ahsanli.com", false},
		{"https://ahsanli.com/login", "ahsanli.com", "https://ahsanli.com", false},
		{"http://127.0.0.1:3001", "127.0.0.1", "http://127.0.0.1:3001", true},
		{"localhost:8080", "localhost", "http://localhost:8080", true},
	}
	for _, tc := range cases {
		spec := NormalizeTarget(tc.raw)
		if spec.Domain != tc.domain || spec.RootURL != tc.rootURL || spec.IsLocalOrIP != tc.isLocal {
			t.Fatalf("NormalizeTarget(%q) = %+v, want domain=%q root=%q local=%v",
				tc.raw, spec, tc.domain, tc.rootURL, tc.isLocal)
		}
	}
}

func TestNativeHTTPXAndSecurityScanAgainstLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.URL.Path == "/.git/HEAD" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		if r.URL.Path == "/api/items" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "TestServer/2.4.1")
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		_, _ = w.Write([]byte(`<html><head><title>Practice Lab</title></head><body><a href="/api/items">API</a></body></html>`))
	}))
	defer srv.Close()

	ctx := context.Background()

	// 1. Subfinder native fallback seeds localhost:port without needing external subfinder binary
	sf := &SubfinderRunner{BinaryPath: ""}
	hosts, err := sf.Enumerate(ctx, srv.URL)
	if err != nil {
		t.Fatalf("Enumerate returned unexpected error: %v", err)
	}
	if len(hosts) == 0 {
		t.Fatalf("expected at least 1 host from Enumerate, got 0")
	}

	// 2. Native HTTPX prober extracts status, title, tech, and internal endpoints
	hx := &HTTPXRunner{BinaryPath: ""}
	probes, err := hx.Probe(ctx, []string{srv.URL})
	if err != nil {
		t.Fatalf("Probe returned unexpected error: %v", err)
	}
	if len(probes) != 1 {
		t.Fatalf("expected 1 probe result, got %d", len(probes))
	}
	if probes[0].StatusCode != 200 || probes[0].Title != "Practice Lab" {
		t.Fatalf("unexpected probe metadata: %+v", probes[0])
	}
	foundChild := false
	for _, ep := range probes[0].Endpoints {
		if strings.HasSuffix(ep, "/api/items") {
			foundChild = true
			break
		}
	}
	if !foundChild {
		t.Fatalf("expected /api/items endpoint in %v", probes[0].Endpoints)
	}

	// 3. Native security scanner detects CORS reflection, missing headers, server leak, and .git/HEAD
	nc := &NucleiRunner{BinaryPath: ""}
	findings, err := nc.Scan(ctx, []string{srv.URL}, nil)
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("expected multiple findings (CORS, headers, .git/HEAD, server disclosure), got %d: %+v", len(findings), findings)
	}
	seenIDs := make(map[string]bool)
	for _, f := range findings {
		seenIDs[f.TemplateID] = true
	}
	for _, expectedID := range []string{"cors-arbitrary-origin-reflection", "exposed-git-head", "http-missing-security-headers", "http-tech-version-disclosure"} {
		if !seenIDs[expectedID] {
			t.Fatalf("expected finding %q in %v", expectedID, seenIDs)
		}
	}
}
