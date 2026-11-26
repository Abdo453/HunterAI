package arsenal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// TargetSpec holds normalized domain, host:port, and seed URLs derived from any user target input.
type TargetSpec struct {
	Raw          string
	Domain       string
	HostWithPort string
	RootURL      string
	SeedURLs     []string
	IsLocalOrIP  bool
}

// NormalizeTarget parses a bare domain, host:port, IP, or full http/https URL into consistent scan fields.
func NormalizeTarget(rawTarget string) TargetSpec {
	trimmed := strings.TrimSpace(rawTarget)
	spec := TargetSpec{Raw: trimmed}
	if trimmed == "" {
		return spec
	}

	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
			host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
			hostPort := strings.TrimSuffix(strings.ToLower(u.Host), ".")
			spec.Domain = host
			spec.HostWithPort = hostPort
			scheme := strings.ToLower(u.Scheme)
			spec.RootURL = scheme + "://" + hostPort
			if u.Path != "" && u.Path != "/" {
				spec.SeedURLs = append(spec.SeedURLs, trimmed)
			}
			spec.SeedURLs = append(spec.SeedURLs, spec.RootURL)
		}
	}

	if spec.Domain == "" {
		clean := strings.TrimSuffix(strings.ToLower(strings.SplitN(trimmed, "/", 2)[0]), ".")
		spec.HostWithPort = clean
		if strings.HasPrefix(clean, "[") {
			if end := strings.IndexByte(clean, ']'); end != -1 {
				spec.Domain = clean[1:end]
			}
		} else if h, _, err := net.SplitHostPort(clean); err == nil {
			spec.Domain = strings.TrimSuffix(h, ".")
		} else {
			spec.Domain = clean
		}

		isExplicitPort := spec.HostWithPort != spec.Domain
		if isExplicitPort {
			spec.RootURL = "http://" + spec.HostWithPort
			spec.SeedURLs = []string{"http://" + spec.HostWithPort, "https://" + spec.HostWithPort}
		} else {
			spec.RootURL = "https://" + spec.Domain
			spec.SeedURLs = []string{"https://" + spec.Domain, "http://" + spec.Domain}
		}
	}

	d := spec.Domain
	if net.ParseIP(d) != nil ||
		d == "localhost" ||
		d == "localhost.localdomain" ||
		strings.HasSuffix(d, ".localhost") ||
		strings.HasSuffix(d, ".local") ||
		strings.HasSuffix(d, ".example") ||
		strings.HasSuffix(d, ".invalid") ||
		strings.HasSuffix(d, ".test") {
		spec.IsLocalOrIP = true
	}

	return spec
}

type SubfinderRunner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewSubfinderRunner() *SubfinderRunner {
	path, err := exec.LookPath("subfinder")
	if err != nil {
		path = ""
	}
	return &SubfinderRunner{
		BinaryPath: path,
		Timeout:    45 * time.Second,
	}
}

var commonSubdomainPrefixes = []string{
	"www",
	"api",
	"app",
	"admin",
	"portal",
	"mail",
	"dev",
	"staging",
	"auth",
}

func (s *SubfinderRunner) Enumerate(ctx context.Context, rawTarget string) ([]string, error) {
	spec := NormalizeTarget(rawTarget)
	if spec.Domain == "" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var results []string
	addHost := func(h string) {
		clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if clean != "" && !seen[clean] {
			seen[clean] = true
			results = append(results, clean)
		}
	}

	// Always seed the primary target host (preserve host:port when specified).
	if spec.HostWithPort != "" {
		addHost(spec.HostWithPort)
	}
	addHost(spec.Domain)

	// Optional external subfinder CLI when installed on PATH for public domains.
	if s.BinaryPath != "" && !spec.IsLocalOrIP && strings.Contains(spec.Domain, ".") {
		c, cancel := context.WithTimeout(ctx, s.Timeout)
		cmd := exec.CommandContext(c, s.BinaryPath, "-d", spec.Domain, "-silent")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		log.Printf("[Arsenal:Subfinder] Running subfinder CLI on: %s", spec.Domain)
		if err := cmd.Run(); err != nil {
			log.Printf("[Arsenal:Subfinder] External subfinder failed (%v); continuing with native Go discovery", err)
		} else {
			scanner := bufio.NewScanner(&stdout)
			for scanner.Scan() {
				addHost(scanner.Text())
			}
		}
		cancel()
	} else {
		log.Printf("[Arsenal:Subfinder] Native Go discovery mode active for %s (external subfinder optional)", spec.Domain)
	}

	// Native Go passive CT log (crt.sh) + concurrent common-subdomain DNS resolution for public domains.
	if !spec.IsLocalOrIP && strings.Contains(spec.Domain, ".") {
		var wg sync.WaitGroup
		var mu sync.Mutex
		candidates := make([]string, 0, len(commonSubdomainPrefixes))
		for _, prefix := range commonSubdomainPrefixes {
			candidates = append(candidates, prefix+"."+spec.Domain)
		}

		// Best-effort crt.sh lookup (4s timeout)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctCtx, http.MethodGet, "https://crt.sh/?q=%25."+url.QueryEscape(spec.Domain)+"&output=json", nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "ARTEX-Pro/1.0")
			client := &http.Client{Timeout: 4 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var rows []struct {
				NameValue string `json:"name_value"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 512*1024)).Decode(&rows); err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			count := 0
			for _, row := range rows {
				for _, line := range strings.Split(row.NameValue, "\n") {
					n := strings.TrimSpace(strings.ToLower(line))
					n = strings.TrimPrefix(n, "*.")
					if n != "" && (n == spec.Domain || strings.HasSuffix(n, "."+spec.Domain)) {
						candidates = append(candidates, n)
						count++
						if count >= 25 {
							return
						}
					}
				}
			}
		}()

		// Resolve primary + common subdomains concurrently
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, prefix := range commonSubdomainPrefixes {
				sub := prefix + "." + spec.Domain
				dnsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				addrs, err := net.DefaultResolver.LookupHost(dnsCtx, sub)
				cancel()
				if err == nil && len(addrs) > 0 {
					mu.Lock()
					addHost(sub)
					mu.Unlock()
				}
			}
		}()

		wg.Wait()

		// Add unique CT names discovered above (capped to keep probing fast)
		mu.Lock()
		for _, cand := range candidates {
			if strings.HasPrefix(cand, "www.") && !seen[cand] {
				continue
			}
			if cand != "" && (cand == spec.Domain || strings.HasSuffix(cand, "."+spec.Domain)) {
				// Only add crt.sh subdomains if they were explicitly from CT (beyond static prefix list)
				isStatic := false
				for _, prefix := range commonSubdomainPrefixes {
					if cand == prefix+"."+spec.Domain {
						isStatic = true
						break
					}
				}
				if !isStatic {
					addHost(cand)
					if len(results) >= 20 {
						break
					}
				}
			}
		}
		mu.Unlock()
	}

	log.Printf("[Arsenal:Subfinder] Discovered %d host targets for %s", len(results), spec.Domain)
	return results, nil
}
