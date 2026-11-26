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

type NucleiFinding struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	CurlCommand      string   `json:"curl-command"`
}

type NucleiRunner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewNucleiRunner() *NucleiRunner {
	path, err := exec.LookPath("nuclei")
	if err != nil {
		path = ""
	}
	return &NucleiRunner{
		BinaryPath: path,
		Timeout:    180 * time.Second,
	}
}

var versionLeakRe = regexp.MustCompile(`[A-Za-z0-9_-]+/\d+\.\d+(?:\.\d+)?`)

func makeNativeFinding(templateID, name, severity, description, matchedAt, curlCmd string, tags ...string) NucleiFinding {
	var f NucleiFinding
	f.TemplateID = templateID
	f.Info.Name = name
	f.Info.Severity = strings.ToLower(severity)
	f.Info.Description = description
	f.Info.Tags = tags
	f.Type = "http"
	f.MatchedAt = matchedAt
	f.CurlCommand = curlCmd
	if u, err := url.Parse(matchedAt); err == nil {
		f.Host = u.Host
	}
	return f
}

func scanSingleEndpointNative(ctx context.Context, client *http.Client, noRedirectClient *http.Client, rawURL string) []NucleiFinding {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	var findings []NucleiFinding

	// 1. Baseline request & security headers / cookie / TLS inspection
	reqCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-Pro/1.0)")
	resp, err := client.Do(req)
	cancel()
	if err != nil {
		return nil
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()
	bodyStr := string(bodyBytes)

	// Missing security headers audit (consolidate to keep findings high-signal)
	var missing []string
	if strings.EqualFold(u.Scheme, "https") && resp.Header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		missing = append(missing, "X-Frame-Options")
	}
	if resp.Header.Get("X-Content-Type-Options") == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if len(missing) > 0 {
		findings = append(findings, makeNativeFinding(
			"http-missing-security-headers",
			"Missing HTTP Security Hardening Headers",
			"low",
			fmt.Sprintf("HTTP %d response at %s omits recommended hardening headers: %s", resp.StatusCode, rawURL, strings.Join(missing, ", ")),
			rawURL,
			fmt.Sprintf("curl -sI %q", rawURL),
			"headers", "hardening",
		))
	}

	// Clickjacking missing XFO / frame-ancestors when HTML renders
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
		resp.Header.Get("X-Frame-Options") == "" &&
		!strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		findings = append(findings, makeNativeFinding(
			"clickjacking-missing-frame-protection",
			"Clickjacking Defense Missing (No XFO / CSP frame-ancestors)",
			"low",
			fmt.Sprintf("HTML document at %s returned HTTP %d without X-Frame-Options or CSP frame-ancestors.", rawURL, resp.StatusCode),
			rawURL,
			fmt.Sprintf("curl -sI %q", rawURL),
			"clickjacking", "headers",
		))
	}

	// Plaintext HTTP login / missing redirect to HTTPS check
	if strings.EqualFold(u.Scheme, "http") && resp.StatusCode == http.StatusOK {
		hasPasswordInput := strings.Contains(strings.ToLower(bodyStr), `type="password"`) || strings.Contains(strings.ToLower(bodyStr), `type='password'`)
		sev := "info"
		desc := fmt.Sprintf("Plaintext HTTP endpoint %s responded 200 OK without redirecting to HTTPS.", rawURL)
		if hasPasswordInput {
			sev = "medium"
			desc = fmt.Sprintf("Plaintext HTTP endpoint %s serves a password form over unencrypted HTTP.", rawURL)
		}
		findings = append(findings, makeNativeFinding(
			"plaintext-http-endpoint",
			"Cleartext HTTP Endpoint Active",
			sev,
			desc,
			rawURL,
			fmt.Sprintf("curl -iL %q", rawURL),
			"tls", "transport",
		))
	}

	// Server / X-Powered-By version disclosure
	var disclosures []string
	for _, hdr := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if val := strings.TrimSpace(resp.Header.Get(hdr)); val != "" && versionLeakRe.MatchString(val) {
			disclosures = append(disclosures, fmt.Sprintf("%s: %s", hdr, val))
		}
	}
	if len(disclosures) > 0 {
		findings = append(findings, makeNativeFinding(
			"http-tech-version-disclosure",
			"Server / Framework Version Disclosure",
			"info",
			fmt.Sprintf("Response headers expose software version strings: %s", strings.Join(disclosures, "; ")),
			rawURL,
			fmt.Sprintf("curl -sI %q", rawURL),
			"tech", "disclosure",
		))
	}

	// Cookie flags check
	for _, setCookie := range resp.Header.Values("Set-Cookie") {
		lowCookie := strings.ToLower(setCookie)
		name := strings.SplitN(setCookie, "=", 2)[0]
		var issues []string
		if !strings.Contains(lowCookie, "httponly") {
			issues = append(issues, "missing HttpOnly")
		}
		if strings.EqualFold(u.Scheme, "https") && !strings.Contains(lowCookie, "secure") {
			issues = append(issues, "missing Secure")
		}
		if len(issues) > 0 {
			findings = append(findings, makeNativeFinding(
				"cookie-missing-security-flags",
				fmt.Sprintf("Cookie %q Missing Security Flags", strings.TrimSpace(name)),
				"low",
				fmt.Sprintf("Set-Cookie header (%s) lacks: %s", strings.TrimSpace(name), strings.Join(issues, ", ")),
				rawURL,
				fmt.Sprintf("curl -sI %q", rawURL),
				"cookie", "session",
			))
			break
		}
	}

	// TLS certificate expiry / mismatch inspection
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		now := time.Now()
		if now.After(cert.NotAfter) {
			findings = append(findings, makeNativeFinding(
				"expired-ssl-certificate",
				"Expired TLS Certificate Detected",
				"medium",
				fmt.Sprintf("TLS certificate CN=%s expired at %s.", cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
				rawURL,
				fmt.Sprintf("curl -vI %q", rawURL),
				"tls", "ssl",
			))
		}
	}

	// 2. Active CORS origin reflection check
	corsCtx, corsCancel := context.WithTimeout(ctx, 5*time.Second)
	corsReq, err := http.NewRequestWithContext(corsCtx, http.MethodGet, rawURL, nil)
	if err == nil {
		corsReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-Pro/1.0)")
		corsReq.Header.Set("Origin", "https://evil.example")
		if corsResp, cErr := noRedirectClient.Do(corsReq); cErr == nil {
			acao := strings.TrimSpace(corsResp.Header.Get("Access-Control-Allow-Origin"))
			acac := strings.EqualFold(strings.TrimSpace(corsResp.Header.Get("Access-Control-Allow-Credentials")), "true")
			corsResp.Body.Close()
			if acao == "https://evil.example" || (acao == "*" && acac) {
				sev := "medium"
				if acac {
					sev = "high"
				}
				findings = append(findings, makeNativeFinding(
					"cors-arbitrary-origin-reflection",
					"Permissive CORS Origin Reflection",
					sev,
					fmt.Sprintf("Sending Origin: https://evil.example produced Access-Control-Allow-Origin: %s (Allow-Credentials: %v).", acao, acac),
					rawURL,
					fmt.Sprintf("curl -i -H \"Origin: https://evil.example\" %q", rawURL),
					"cors", "misconfig",
				))
			}
		}
	}
	corsCancel()

	// 3. Baseline 404 fingerprint check to eliminate soft-404 catch-all false positives
	nfURL := origin + "/__artex_nonexistent_probe_918273__"
	nfStatus := 404
	nfLen := -1
	nfCtx, nfCancel := context.WithTimeout(ctx, 4*time.Second)
	if nfReq, err := http.NewRequestWithContext(nfCtx, http.MethodGet, nfURL, nil); err == nil {
		nfReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-Pro/1.0)")
		if nfResp, err := noRedirectClient.Do(nfReq); err == nil {
			nfBody, _ := io.ReadAll(io.LimitReader(nfResp.Body, 32*1024))
			nfResp.Body.Close()
			nfStatus = nfResp.StatusCode
			nfLen = len(nfBody)
		}
	}
	nfCancel()

	// 4. Sensitive exposed path verification with strict content verification
	sensitiveProbes := []struct {
		path      string
		id        string
		title     string
		severity  string
		validator func(status int, ct, body string) bool
	}{
		{
			path:     "/.env",
			id:       "exposed-dotenv-file",
			title:    "Exposed Environment File (.env)",
			severity: "critical",
			validator: func(status int, ct, body string) bool {
				return status == 200 && !strings.Contains(strings.ToLower(ct), "text/html") &&
					(strings.Contains(body, "APP_KEY=") || strings.Contains(body, "DB_PASSWORD=") || strings.Contains(body, "SECRET_KEY=") || strings.Contains(body, "DATABASE_URL="))
			},
		},
		{
			path:     "/.git/HEAD",
			id:       "exposed-git-head",
			title:    "Exposed Git Repository Metadata (.git/HEAD)",
			severity: "high",
			validator: func(status int, ct, body string) bool {
				return status == 200 && strings.Contains(body, "ref: refs/")
			},
		},
		{
			path:     "/phpinfo.php",
			id:       "exposed-phpinfo",
			title:    "Exposed PHPInfo Diagnostic Page",
			severity: "medium",
			validator: func(status int, ct, body string) bool {
				return status == 200 && strings.Contains(body, "PHP Version") && strings.Contains(body, "phpinfo()")
			},
		},
		{
			path:     "/swagger.json",
			id:       "exposed-swagger-spec",
			title:    "Public OpenAPI / Swagger Specification Exposed",
			severity: "info",
			validator: func(status int, ct, body string) bool {
				return status == 200 && strings.Contains(body, `"paths"`) && (strings.Contains(body, `"swagger"`) || strings.Contains(body, `"openapi"`))
			},
		},
		{
			path:     "/openapi.json",
			id:       "exposed-openapi-spec",
			title:    "Public OpenAPI Specification Exposed",
			severity: "info",
			validator: func(status int, ct, body string) bool {
				return status == 200 && strings.Contains(body, `"openapi"`) && strings.Contains(body, `"paths"`)
			},
		},
		{
			path:     "/actuator/health",
			id:       "exposed-spring-actuator",
			title:    "Exposed Spring Boot Actuator Health Endpoint",
			severity: "low",
			validator: func(status int, ct, body string) bool {
				return status == 200 && strings.Contains(strings.ToLower(ct), "application/json") && strings.Contains(body, `"status"`)
			},
		},
	}

	for _, probe := range sensitiveProbes {
		probeURL := origin + probe.path
		pCtx, pCancel := context.WithTimeout(ctx, 4*time.Second)
		pReq, pErr := http.NewRequestWithContext(pCtx, http.MethodGet, probeURL, nil)
		if pErr == nil {
			pReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARTEX-Pro/1.0)")
			if pResp, err := noRedirectClient.Do(pReq); err == nil {
				pBytes, _ := io.ReadAll(io.LimitReader(pResp.Body, 32*1024))
				pResp.Body.Close()
				pBody := string(pBytes)
				// Skip if identical to soft-404 fallback page
				if !(nfStatus == pResp.StatusCode && nfLen > 0 && len(pBytes) == nfLen) && probe.validator(pResp.StatusCode, pResp.Header.Get("Content-Type"), pBody) {
					snippet := strings.TrimSpace(pBody)
					if len(snippet) > 220 {
						snippet = snippet[:220] + "..."
					}
					findings = append(findings, makeNativeFinding(
						probe.id,
						probe.title,
						probe.severity,
						fmt.Sprintf("HTTP %d matched verification signature at %s\nSnippet: %s", pResp.StatusCode, probeURL, snippet),
						probeURL,
						fmt.Sprintf("curl -sS %q", probeURL),
						"exposure", "misconfig",
					))
				}
			}
		}
		pCancel()
	}

	return findings
}

func nativeSecurityScan(ctx context.Context, targets []string) []NucleiFinding {
	client := &http.Client{
		Timeout: 7 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	noRedirectClient := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var roots []string
	seenRoot := make(map[string]bool)
	for _, t := range targets {
		trimmed := strings.TrimSpace(t)
		if trimmed == "" {
			continue
		}
		if u, err := url.Parse(trimmed); err == nil && u.Scheme != "" && u.Host != "" {
			key := u.Scheme + "://" + u.Host
			if !seenRoot[key] {
				seenRoot[key] = true
				roots = append(roots, trimmed)
				if len(roots) >= 6 {
					break
				}
			}
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var all []NucleiFinding

	for _, targetURL := range roots {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			res := scanSingleEndpointNative(ctx, client, noRedirectClient, u)
			if len(res) > 0 {
				mu.Lock()
				all = append(all, res...)
				mu.Unlock()
			}
		}(targetURL)
	}
	wg.Wait()
	return all
}

func (n *NucleiRunner) Scan(ctx context.Context, targets []string, severity []string) ([]NucleiFinding, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var collected []NucleiFinding
	seen := make(map[string]bool)
	appendUnique := func(items []NucleiFinding) {
		for _, f := range items {
			key := f.TemplateID + "|" + f.MatchedAt
			if !seen[key] {
				seen[key] = true
				collected = append(collected, f)
			}
		}
	}

	if n.BinaryPath != "" {
		c, cancel := context.WithTimeout(ctx, n.Timeout)
		args := []string{"-silent", "-jsonl"}
		if len(severity) > 0 {
			args = append(args, "-severity", strings.Join(severity, ","))
		} else {
			args = append(args, "-severity", "low,medium,high,critical")
		}

		cmd := exec.CommandContext(c, n.BinaryPath, args...)
		cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		log.Printf("[Arsenal:Nuclei] Launching Nuclei scan against %d endpoints...", len(targets))
		err := cmd.Run()
		cancel()
		if err == nil || stdout.Len() > 0 {
			var cliFindings []NucleiFinding
			scanner := bufio.NewScanner(&stdout)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				var f NucleiFinding
				if err := json.Unmarshal([]byte(line), &f); err == nil {
					cliFindings = append(cliFindings, f)
				}
			}
			appendUnique(cliFindings)
		} else {
			log.Printf("[Arsenal:Nuclei] External Nuclei failed (%v: %s); falling back to native Go security checks", err, strings.TrimSpace(stderr.String()))
		}
	} else {
		log.Printf("[Arsenal:Nuclei] Running native Go HTTP security & exposure audit across %d endpoints...", len(targets))
	}

	// Always run native fast HTTP/CORS/TLS/headers/sensitive-file checks to guarantee baseline telemetry.
	nativeFindings := nativeSecurityScan(ctx, targets)
	appendUnique(nativeFindings)

	log.Printf("[Arsenal:Nuclei] Completed vulnerability sweep: %d findings recorded", len(collected))
	return collected, nil
}
