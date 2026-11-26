package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"artex-pro/internal/agent"
	"artex-pro/internal/api"
	"artex-pro/internal/database"
)

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func main() {
	target := flag.String("target", "", "Target domain to assess (e.g. example.com)")
	serverMode := flag.Bool("server", false, "Run in HTTP API Server daemon mode")
	port := flag.Int("port", envIntOrDefault("ARTEX_PORT", 7071), "HTTP API server port")
	bindAddr := flag.String("bind", strings.TrimSpace(os.Getenv("ARTEX_BIND_ADDR")), "HTTP API bind address (default 127.0.0.1:<port>)")
	dbHost := flag.String("db-host", envOrDefault("ARTEX_DB_HOST", "127.0.0.1"), "PostgreSQL host")
	dbPort := flag.Int("db-port", envIntOrDefault("ARTEX_DB_PORT", 5432), "PostgreSQL port")
	dbUser := flag.String("db-user", envOrDefault("ARTEX_DB_USER", "artex"), "PostgreSQL user")
	dbPass := flag.String("db-pass", os.Getenv("ARTEX_DB_PASSWORD"), "PostgreSQL password (or set ARTEX_DB_PASSWORD)")
	dbName := flag.String("db-name", envOrDefault("ARTEX_DB_NAME", "artex_pro"), "PostgreSQL database name")
	dbSSLMode := flag.String("db-sslmode", strings.TrimSpace(os.Getenv("ARTEX_DB_SSLMODE")), "PostgreSQL sslmode (disable|allow|prefer|require|verify-ca|verify-full)")
	flag.Parse()

	if strings.TrimSpace(*bindAddr) != "" {
		_ = os.Setenv("ARTEX_BIND_ADDR", strings.TrimSpace(*bindAddr))
	}

	if strings.TrimSpace(*dbPass) == "" && strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_DB_ALLOW_EMPTY_PASSWORD"))) != "1" {
		log.Fatalf("[-] Database password is required: pass -db-pass or set ARTEX_DB_PASSWORD (no insecure default password).")
	}

	fmt.Println("==================================================================")
	fmt.Println("  ⚡ ARTEX-Pro Go High-Concurrency Autonomous Core Engine")
	fmt.Println("==================================================================")

	// 1. Connect to PostgreSQL
	db, err := database.ConnectWithSSLMode(*dbHost, *dbPort, *dbUser, *dbPass, *dbName, *dbSSLMode)
	if err != nil {
		log.Fatalf("[-] Database connection failed: %v", err)
	}
	defer db.Close()

	// 2. Server Mode
	if *serverMode {
		srv := api.NewAPIServer(db, *port)
		if err := srv.Start(); err != nil {
			log.Fatalf("[-] API server stopped: %v", err)
		}
		return
	}

	// 3. One-shot target scan mode
	if *target == "" {
		fmt.Println("[*] No target specified.")
		fmt.Println("    Usage 1 (Scan Target):  ./artex-server -target example.com")
		fmt.Println("    Usage 2 (Daemon API):   ./artex-server -server -port 7071")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Received interrupt signal. Terminating tasks gracefully...")
		cancel()
	}()

	orchestrator := agent.NewOrchestrator(db)
	summary, err := orchestrator.RunAutonomousMission(ctx, *target)
	if err != nil {
		log.Fatalf("[-] Orchestrator mission failed: %v", err)
	}

	fmt.Println("------------------------------------------------------------------")
	fmt.Println("  🏁 ARTEX-Pro Autonomous Mission Completed Successfully")
	fmt.Printf("  • Target Domain:       %s\n", summary.TargetDomain)
	fmt.Printf("  • Discovered Assets:   %d assets\n", summary.TotalAssets)
	fmt.Printf("  • Live Endpoints:      %d HTTP/HTTPS services\n", summary.LiveEndpoints)
	fmt.Printf("  • Verified Findings:   %d vulnerabilities in PostgreSQL\n", summary.TotalFindings)
	fmt.Printf("  • Pipeline Duration:   %.2fs (Pure Go Goroutines)\n", summary.DurationSec)
	fmt.Println("==================================================================")
}
