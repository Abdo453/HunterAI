package arsenal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type HTTPXResult struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	Port       string   `json:"port"`
	Title      string   `json:"title"`
	StatusCode int      `json:"status_code"`
	Tech       []string `json:"tech"`
	WebServer  string   `json:"webserver"`
	CDNName    string   `json:"cdn_name"`
}

type HTTPXRunner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewHTTPXRunner() *HTTPXRunner {
	// In Kali Linux / Debian, ProjectDiscovery's httpx is packaged as httpx-toolkit
	path, err := exec.LookPath("httpx-toolkit")
	if err != nil {
		path, err = exec.LookPath("httpx")
		if err != nil {
			path = "/usr/bin/httpx-toolkit"
		}
	}
	return &HTTPXRunner{
		BinaryPath: path,
		Timeout:    120 * time.Second,
	}
}

func (h *HTTPXRunner) Probe(ctx context.Context, hosts []string) ([]HTTPXResult, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	c, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := exec.CommandContext(c, h.BinaryPath, "-silent", "-json", "-status-code", "-title", "-tech-detect")
	cmd.Stdin = strings.NewReader(strings.Join(hosts, "\n"))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[Arsenal:HTTPX] Probing %d hosts for live web endpoints...", len(hosts))
	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("httpx error: %v (stderr: %s)", err, stderr.String())
	}

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

	log.Printf("[Arsenal:HTTPX] Discovered %d live HTTP/HTTPS endpoints", len(results))
	return results, nil
}
