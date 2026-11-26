package arsenal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type HTTPXResult struct {
	URL             string            `json:"url"`
	Input           string            `json:"input"`
	Host            string            `json:"host"`
	Port            string            `json:"port"`
	Title           string            `json:"title"`
	StatusCode      int               `json:"status_code"`
	Tech            []string          `json:"tech"`
	WebServer       string            `json:"webserver"`
	CDNName         string            `json:"cdn_name"`
	SecurityHeaders map[string]bool   `json:"security_headers,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Endpoints       []string          `json:"endpoints,omitempty"`
	TLSIssuer       string            `json:"tls_issuer,omitempty"`
	TLSValid        bool              `json:"tls_valid"`
}

type HTTPXRunner struct {
	BinaryPath string
	Timeout    time.Duration
}

func resolveProjectDiscoveryHTTPX() string {
	for _, name := range []string{"httpx-toolkit", "httpx"} {
		path, err := exec.LookPath(name)
		if err != nil || path == "" {
			continue
		}
		// Reject Python's httpx CLI wrapper on Windows/Linux by requiring ProjectDiscovery signature.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, path, "-version")
		var combined bytes.Buffer
		cmd.Stdout = &combined
		cmd.Stderr = &combined
		_ = cmd.Run()
		cancel()
		out := strings.ToLower(combined.String())
		if strings.Contains(out, "projectdiscovery") || strings.Contains(out, "current version: v") {
			return path
		}
	}
	return ""
}

func NewHTTPXRunner() *HTTPXRunner {
	return &HTTPXRunner{
		BinaryPath: resolveProjectDiscoveryHTTPX(),
		Timeout:    60 * time.Second,
	}
}

var (
	htmlTitleRe  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	htmlLinkRe   = regexp.MustCompile(`(?is)(?:href|src|action)\s*=\s*["']([^"'#\s>]+)["']`)
)

func detectTechnologies(headers http.Header, body string) ([]string, string) {
	seen := make(map[string]bool)
	var tech []string
	addTech := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			tech = append(tech, name)
		}
	}

	server := strings.TrimSpace(headers.Get("Server"))
	if server != "" {
		low := strings.ToLower(server)
		switch {
		case strings.Contains(low, "cloudflare"):
			addTech("Cloudflare")
		case strings.Contains(low, "nginx"):
			addTech("Nginx")
		case strings.Contains(low, "apache"):
			addTech("Apache")
		case strings.Contains(low, "microsoft-iis"):
			addTech("Microsoft IIS")
		case strings.Contains(low, "litespeed"):
			addTech("LiteSpeed")
		default:
			addTech(server)
		}
	}
	if xpb := strings.TrimSpace(headers.Get("X-Powered-By")); xpb != "" {
		addTech(xpb)
	}
	if headers.Get("CF-Ray") != "" {
		addTech("Cloudflare")
	}

	bodyLow := strings.ToLower(body)
	signatures := []struct {
		needle string
		label  string
	}{
		{"__next_data__", "Next.js"},
		{"/_next/static", "Next.js"},
		{"wp-content", "WordPress"},
		{"wp-includes", "WordPress"},
		{"data-reactroot", "React"},
		{"react-dom", "React"},
		{"ng-version", "Angular"},
		{"nuxt", "Nuxt.js"},
		{"jquery", "jQuery"},
		{"bootstrap", "Bootstrap"},
		{"tailwindcss", "Tailwind CSS"},
		{"laravel", "Laravel"},
		{"csrfmiddlewaretoken", "Django"},
		{"swagger-ui", "Swagger UI"},
	}
	for _, sig := range signatures {
		if strings.Contains(bodyLow, sig.needle) {
			addTech(sig.label)
		}
	}
	return tech, server
}

func extractSameHostEndpoints(base *url.URL, body string) []string {
	if base == nil || body == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	matches := htmlLinkRe.FindAllStringSubmatch(body, 80)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		rawRef := strings.TrimSpace(m[1])
		if rawRef == "" || strings.HasPrefix(rawRef, "javascript:") || strings.HasPrefix(rawRef, "mailto:") || strings.HasPrefix(rawRef, "data:") {
			continue
		}
		refURL, err := base.Parse(rawRef)
		if err != nil {
			continue
		}
		if refURL.Scheme != "http" && refURL.Scheme != "https" {
			continue
		}
		if !strings.EqualFold(refURL.Hostname(), base.Hostname()) {
			continue
		}
		refURL.Fragment = ""
		full := refURL.String()
		if !seen[full] {
			seen[full] = true
			out = append(out, full)
			if len(out) >= 25 {
				break
			}
		}
	}
	return out
}

func (h *HTTPXRunner) probeSingleNative(ctx context.Context, client *http.Client, targetHost string) (HTTPXResult, bool) {
	spec := NormalizeTarget(targetHost)
	candidates := spec.SeedURLs
	if len(candidates) == 0 {
		return HTTPXResult{}, false
	}

	for _, candidateURL := range candidates {
		reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, candidateURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-Pro/1.0)")
		req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		cancel()

		bodyStr := string(bodyBytes)
		finalURL := candidateURL
		var parsedFinal *url.URL
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
			parsedFinal = resp.Request.URL
		} else {
			parsedFinal, _ = url.Parse(finalURL)
		}

		title := ""
		if m := htmlTitleRe.FindStringSubmatch(bodyStr); len(m) >= 2 {
			title = strings.Join(strings.Fields(strings.TrimSpace(m[1])), " ")
			if len(title) > 120 {
				title = title[:120]
			}
		}

		tech, server := detectTechnologies(resp.Header, bodyStr)
		hdrs := make(map[string]string)
		for k, vals := range resp.Header {
			if len(vals) > 0 {
				hdrs[k] = strings.Join(vals, ", ")
			}
		}
		secHdrs := map[string]bool{
			"strict-transport-security": resp.Header.Get("Strict-Transport-Security") != "",
			"content-security-policy":   resp.Header.Get("Content-Security-Policy") != "",
			"x-frame-options":           resp.Header.Get("X-Frame-Options") != "",
			"x-content-type-options":    resp.Header.Get("X-Content-Type-Options") != "",
		}

		port := ""
		host := spec.Domain
		if parsedFinal != nil {
			host = parsedFinal.Hostname()
			port = parsedFinal.Port()
			if port == "" {
				if parsedFinal.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
		}

		tlsIssuer := ""
		tlsValid := false
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			tlsIssuer = cert.Issuer.CommonName
			now := time.Now()
			tlsValid = !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
		}

		endpoints := extractSameHostEndpoints(parsedFinal, bodyStr)

		return HTTPXResult{
			URL:             finalURL,
			Input:           targetHost,
			Host:            host,
			Port:            port,
			Title:           title,
			StatusCode:      resp.StatusCode,
			Tech:            tech,
			WebServer:       server,
			CDNName:         resp.Header.Get("CF-Ray"),
			SecurityHeaders: secHdrs,
			Headers:         hdrs,
			Endpoints:       endpoints,
			TLSIssuer:       tlsIssuer,
			TLSValid:        tlsValid,
		}, true
	}

	return HTTPXResult{}, false
}

func (h *HTTPXRunner) probeNative(ctx context.Context, hosts []string) []HTTPXResult {
	client := &http.Client{
		Timeout: 7 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 4,
		},
	}

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []HTTPXResult

	for _, host := range hosts {
		hTrim := strings.TrimSpace(host)
		if hTrim == "" {
			continue
		}
		wg.Add(1)
		go func(targetHost string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if item, ok := h.probeSingleNative(ctx, client, targetHost); ok {
				mu.Lock()
				results = append(results, item)
				mu.Unlock()
			}
		}(hTrim)
	}
	wg.Wait()
	return results
}

func (h *HTTPXRunner) Probe(ctx context.Context, hosts []string) ([]HTTPXResult, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	// Use external ProjectDiscovery httpx CLI if verified installed, otherwise run native Go HTTP prober.
	if h.BinaryPath != "" {
		c, cancel := context.WithTimeout(ctx, h.Timeout)
		cmd := exec.CommandContext(c, h.BinaryPath, "-silent", "-json", "-status-code", "-title", "-tech-detect")
		cmd.Stdin = strings.NewReader(strings.Join(hosts, "\n"))

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		log.Printf("[Arsenal:HTTPX] Probing %d hosts with ProjectDiscovery HTTPX...", len(hosts))
		err := cmd.Run()
		cancel()
		if err == nil || stdout.Len() > 0 {
			var results []HTTPXResult
			scanner := bufio.NewScanner(&stdout)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				var item HTTPXResult
				if err := json.Unmarshal([]byte(line), &item); err == nil {
					results = append(results, item)
				}
			}
			if len(results) > 0 {
				log.Printf("[Arsenal:HTTPX] External HTTPX discovered %d live endpoints", len(results))
				return results, nil
			}
		} else {
			log.Printf("[Arsenal:HTTPX] External HTTPX failed (%v: %s); falling back to native Go prober", err, strings.TrimSpace(stderr.String()))
		}
	} else {
		log.Printf("[Arsenal:HTTPX] Running native Go HTTP/HTTPS prober against %d hosts...", len(hosts))
	}

	results := h.probeNative(ctx, hosts)
	log.Printf("[Arsenal:HTTPX] Native Go prober discovered %d live HTTP/HTTPS endpoints (%s)", len(results), fmt.Sprintf("checked=%d", len(hosts)))
	return results, nil
}
