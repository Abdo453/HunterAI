package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"artex-pro/internal/agent"
	"artex-pro/internal/database"
)

type APIServer struct {
	db           *database.DB
	orchestrator *agent.Orchestrator
	port         int
}

func NewAPIServer(db *database.DB, port int) *APIServer {
	return &APIServer{
		db:           db,
		orchestrator: agent.NewOrchestrator(db),
		port:         port,
	}
}

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", enableCORS(s.handleHealth))
	mux.HandleFunc("/api/v1/stats", enableCORS(s.handleStats))
	mux.HandleFunc("/api/v1/engagements", enableCORS(s.handleEngagements))
	mux.HandleFunc("/api/v1/assets", enableCORS(s.handleAssets))
	mux.HandleFunc("/api/v1/findings", enableCORS(s.handleFindings))
	mux.HandleFunc("/api/v1/scan", enableCORS(s.handleScan))

	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	log.Printf("[API] 🌐 ARTEX-Pro REST API Server listening on http://%s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"engine":    "ARTEX-Pro Go Core",
		"database":  "PostgreSQL 16+",
		"timestamp": time.Now().UTC(),
	})
}

func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var totalAssets, totalFindings, totalEngagements int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM asset_nodes").Scan(&totalAssets)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&totalFindings)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM engagements").Scan(&totalEngagements)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total_assets":      totalAssets,
		"total_findings":    totalFindings,
		"total_engagements": totalEngagements,
		"status":            "ONLINE",
	})
}

func (s *APIServer) handleEngagements(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := s.db.Query(`SELECT id, code, target_url, authorized_scope, status, created_at FROM engagements ORDER BY created_at DESC LIMIT 20`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []map[string]interface{}
	for rows.Next() {
		var id, code, targetURL, scope, status string
		var createdAt time.Time
		if err := rows.Scan(&id, &code, &targetURL, &scope, &status, &createdAt); err == nil {
			list = append(list, map[string]interface{}{
				"id":               id,
				"code":             code,
				"target_url":       targetURL,
				"authorized_scope": scope,
				"status":           status,
				"created_at":       createdAt,
			})
		}
	}

	_ = json.NewEncoder(w).Encode(list)
}

func (s *APIServer) handleAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	target := r.URL.Query().Get("target")

	query := `SELECT id, target_id, kind, value, attributes, created_at FROM asset_nodes`
	var args []interface{}
	if target != "" {
		query += ` WHERE value LIKE $1 OR target_id::text = $2`
		args = append(args, "%"+target+"%", target)
	}
	query += ` ORDER BY id DESC LIMIT 100`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []map[string]interface{}
	for rows.Next() {
		var id, targetID, kind, value string
		var attributes []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &targetID, &kind, &value, &attributes, &createdAt); err == nil {
			var attrMap map[string]interface{}
			_ = json.Unmarshal(attributes, &attrMap)
			list = append(list, map[string]interface{}{
				"id":         id,
				"target_id":  targetID,
				"kind":       kind,
				"value":      value,
				"attributes": attrMap,
				"created_at": createdAt,
			})
		}
	}

	_ = json.NewEncoder(w).Encode(list)
}

func (s *APIServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := s.db.Query(`SELECT id, title, vuln_class, severity, cvss_score, endpoint, status, created_at FROM findings ORDER BY cvss_score DESC LIMIT 50`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []map[string]interface{}
	for rows.Next() {
		var id, title, vulnClass, severity, endpoint, status string
		var cvss float64
		var createdAt time.Time
		if err := rows.Scan(&id, &title, &vulnClass, &severity, &cvss, &endpoint, &status, &createdAt); err == nil {
			list = append(list, map[string]interface{}{
				"id":         id,
				"title":      title,
				"vuln_class": vulnClass,
				"severity":   severity,
				"cvss_score": cvss,
				"endpoint":   endpoint,
				"status":     status,
				"created_at": createdAt,
			})
		}
	}

	_ = json.NewEncoder(w).Encode(list)
}

func (s *APIServer) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Target) == "" {
		http.Error(w, "Invalid target domain", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "QUEUED",
		"target":  req.Target,
		"message": "Autonomous ARTEX-Pro pipeline dispatched in background Goroutine",
	})

	// Dispatch background Goroutine with panic recovery
	go func(target string) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[-] [API] Recovered from background mission panic: %v", r)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		_, _ = s.orchestrator.RunAutonomousMission(ctx, target)
	}(req.Target)
}
