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

type NucleiFinding struct {
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Type         string `json:"type"`
	Host         string `json:"host"`
	MatchedAt    string `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	CurlCommand  string `json:"curl-command"`
}

type NucleiRunner struct {
	BinaryPath string
	Timeout    time.Duration
}

func NewNucleiRunner() *NucleiRunner {
	path, err := exec.LookPath("nuclei")
	if err != nil {
		path = "/usr/bin/nuclei"
	}
	return &NucleiRunner{
		BinaryPath: path,
		Timeout:    300 * time.Second,
	}
}

func (n *NucleiRunner) Scan(ctx context.Context, targets []string, severity []string) ([]NucleiFinding, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	c, cancel := context.WithTimeout(ctx, n.Timeout)
	defer cancel()

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

	log.Printf("[Arsenal:Nuclei] Launching vulnerability sweep against %d endpoints...", len(targets))
	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("nuclei error: %v (stderr: %s)", err, stderr.String())
	}

	var findings []NucleiFinding
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var f NucleiFinding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			findings = append(findings, f)
		}
	}

	log.Printf("[Arsenal:Nuclei] Completed scan: %d vulnerability findings detected", len(findings))
	return findings, nil
}
