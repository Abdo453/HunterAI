package arsenal

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type SubfinderRunner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewSubfinderRunner() *SubfinderRunner {
	path, err := exec.LookPath("subfinder")
	if err != nil {
		path = "/usr/bin/subfinder"
	}
	return &SubfinderRunner{
		BinaryPath: path,
		Timeout:    90 * time.Second,
	}
}

func (s *SubfinderRunner) Enumerate(ctx context.Context, domain string) ([]string, error) {
	c, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	cmd := exec.CommandContext(c, s.BinaryPath, "-d", domain, "-silent")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[Arsenal:Subfinder] Running enumeration on: %s", domain)
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("subfinder error: %v (stderr: %s)", err, stderr.String())
	}

	var results []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub != "" && !seen[sub] {
			seen[sub] = true
			results = append(results, sub)
		}
	}

	log.Printf("[Arsenal:Subfinder] Discovered %d unique subdomains for %s", len(results), domain)
	return results, nil
}
