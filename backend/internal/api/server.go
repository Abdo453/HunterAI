package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"artex-pro/internal/agent"
	"artex-pro/internal/database"
)

// APIServer exposes the ARTEX-Pro HTTP REST API backed by PostgreSQL.
type APIServer struct {
	db           *database.DB
	orchestrator *agent.Orchestrator
	port         int
}

// NewAPIServer constructs an APIServer bound to the provided database handle and TCP port.
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
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// Handler builds and returns the HTTP router with CORS enabled across all v1 endpoints.
func (s *APIServer) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", enableCORS(s.handleHealth))
	mux.HandleFunc("/api/v1/stats", enableCORS(s.handleStats))
	mux.HandleFunc("/api/v1/engagements", enableCORS(s.handleEngagements))
	mux.HandleFunc("/api/v1/assets", enableCORS(s.handleAssets))
	mux.HandleFunc("/api/v1/findings", enableCORS(s.handleFindings))
	mux.HandleFunc("/api/v1/tasks", enableCORS(s.handleTasks))
	mux.HandleFunc("/api/v1/audit", enableCORS(s.handleAudit))
	mux.HandleFunc("/api/v1/scan", enableCORS(s.handleScan))

	return mux
}

// Start begins serving the ARTEX-Pro REST API on the configured port.
func (s *APIServer) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	log.Printf("[API] ARTEX-Pro REST API Server listening on http://%s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *APIServer) hasDB() bool {
	return s != nil && s.db != nil && s.db.DB != nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": message,
	})
}

func decodeJSONObject(raw []byte) map[string]interface{} {
	out := make(map[string]interface{})
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return make(map[string]interface{})
	}
	return out
}

func (s *APIServer) requireGETWithDB(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return false
	}
	if !s.hasDB() {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return false
	}
	return true
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	resp := map[string]interface{}{
		"engine":    "ARTEX-Pro Go Core",
		"timestamp": time.Now().UTC(),
	}

	if !s.hasDB() {
		resp["status"] = "degraded"
		resp["database"] = "disconnected"
		resp["error"] = "database handle is not configured"
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.PingContext(ctx); err != nil {
		resp["status"] = "degraded"
		resp["database"] = "disconnected"
		resp["error"] = err.Error()
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	resp["status"] = "healthy"
	resp["database"] = "connected"
	writeJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !s.hasDB() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"total_assets":      0,
			"total_findings":    0,
			"total_engagements": 0,
			"status":            "DEGRADED",
			"error":             "database unavailable",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	counts := make([]int, 3)
	queries := []string{
		"SELECT COUNT(*) FROM asset_nodes",
		"SELECT COUNT(*) FROM findings",
		"SELECT COUNT(*) FROM engagements",
	}
	for i, q := range queries {
		if err := s.db.QueryRowContext(ctx, q).Scan(&counts[i]); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"total_assets":      counts[0],
				"total_findings":    counts[1],
				"total_engagements": counts[2],
				"status":            "DEGRADED",
				"error":             err.Error(),
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_assets":      counts[0],
		"total_findings":    counts[1],
		"total_engagements": counts[2],
		"status":            "ONLINE",
	})
}

func (s *APIServer) handleEngagements(w http.ResponseWriter, r *http.Request) {
	if !s.requireGETWithDB(w, r) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, code, target_url, authorized_scope, status, started_at, finished_at
		FROM engagements
		ORDER BY started_at DESC
		LIMIT 20`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	list := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, code, targetURL, scope, status string
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(&id, &code, &targetURL, &scope, &status, &startedAt, &finishedAt); err != nil {
			log.Printf("[API] engagements row scan error: %v", err)
			continue
		}
		item := map[string]interface{}{
			"id":               id,
			"code":             code,
			"target_url":       targetURL,
			"authorized_scope": scope,
			"status":           status,
			"started_at":       nil,
			"created_at":       nil,
			"finished_at":      nil,
		}
		if startedAt.Valid {
			item["started_at"] = startedAt.Time
			item["created_at"] = startedAt.Time
		}
		if finishedAt.Valid {
			item["finished_at"] = finishedAt.Time
		}
		list = append(list, item)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *APIServer) handleAssets(w http.ResponseWriter, r *http.Request) {
	if !s.requireGETWithDB(w, r) {
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("target"))
	engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))

	query := `SELECT a.id, COALESCE(a.target_id::text, ''), a.kind, a.value, COALESCE(a.attributes, '{}'::jsonb), a.first_seen
		FROM asset_nodes a
		LEFT JOIN targets t ON a.target_id = t.id`
	var conditions []string
	var args []interface{}

	if target != "" {
		p1 := len(args) + 1
		p2 := len(args) + 2
		conditions = append(conditions, fmt.Sprintf("(a.value LIKE $%d OR a.target_id::text = $%d)", p1, p2))
		args = append(args, "%"+target+"%", target)
	}
	if engagementID != "" {
		p := len(args) + 1
		conditions = append(conditions, fmt.Sprintf("t.engagement_id::text = $%d", p))
		args = append(args, engagementID)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY a.first_seen DESC, a.id DESC LIMIT 100"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	list := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, targetID, kind, value string
		var attributes []byte
		var firstSeen sql.NullTime
		if err := rows.Scan(&id, &targetID, &kind, &value, &attributes, &firstSeen); err != nil {
			log.Printf("[API] asset_nodes row scan error: %v", err)
			continue
		}
		item := map[string]interface{}{
			"id":         id,
			"target_id":  targetID,
			"kind":       kind,
			"value":      value,
			"attributes": decodeJSONObject(attributes),
			"first_seen": nil,
			"created_at": nil,
		}
		if firstSeen.Valid {
			item["first_seen"] = firstSeen.Time
			item["created_at"] = firstSeen.Time
		}
		list = append(list, item)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *APIServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	if !s.requireGETWithDB(w, r) {
		return
	}

	engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))

	query := `SELECT id, COALESCE(engagement_id::text, ''), COALESCE(target_id::text, ''), title, vuln_class, severity,
		COALESCE(cvss_score, 0.0), COALESCE(confidence, 0.0),
		COALESCE(NULLIF(endpoint, ''), evidence, ''), COALESCE(evidence, ''),
		COALESCE(status, 'CONFIRMED'), created_at
		FROM findings`
	var args []interface{}
	if engagementID != "" {
		query += " WHERE engagement_id::text = $1"
		args = append(args, engagementID)
	}
	query += " ORDER BY COALESCE(cvss_score, 0.0) DESC, created_at DESC LIMIT 50"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	list := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, engID, targetID, title, vulnClass, severity, endpoint, evidence, status string
		var cvss, confidence float64
		var createdAt sql.NullTime
		if err := rows.Scan(
			&id, &engID, &targetID, &title, &vulnClass, &severity,
			&cvss, &confidence, &endpoint, &evidence, &status, &createdAt,
		); err != nil {
			log.Printf("[API] findings row scan error: %v", err)
			continue
		}
		item := map[string]interface{}{
			"id":            id,
			"engagement_id": engID,
			"target_id":     targetID,
			"title":         title,
			"vuln_class":    vulnClass,
			"severity":      severity,
			"cvss_score":    cvss,
			"confidence":    confidence,
			"endpoint":      endpoint,
			"evidence":      evidence,
			"status":        status,
			"created_at":    nil,
		}
		if createdAt.Valid {
			item["created_at"] = createdAt.Time
		}
		list = append(list, item)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *APIServer) handleTasks(w http.ResponseWriter, r *http.Request) {
	if !s.requireGETWithDB(w, r) {
		return
	}

	engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))

	query := `SELECT id, COALESCE(engagement_id::text, ''), agent_role, title, status, COALESCE(priority, 5),
		COALESCE(input_context, '{}'::jsonb), COALESCE(output_summary, '{}'::jsonb),
		created_at, updated_at
		FROM tasks`
	var args []interface{}
	if engagementID != "" {
		query += " WHERE engagement_id::text = $1"
		args = append(args, engagementID)
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	list := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, engID, agentRole, title, status string
		var priority int
		var inputContext, outputSummary []byte
		var createdAt, updatedAt sql.NullTime
		if err := rows.Scan(
			&id, &engID, &agentRole, &title, &status, &priority,
			&inputContext, &outputSummary, &createdAt, &updatedAt,
		); err != nil {
			log.Printf("[API] tasks row scan error: %v", err)
			continue
		}
		item := map[string]interface{}{
			"id":             id,
			"engagement_id":  engID,
			"agent_role":     agentRole,
			"title":          title,
			"status":         status,
			"priority":       priority,
			"input_context":  decodeJSONObject(inputContext),
			"output_summary": decodeJSONObject(outputSummary),
			"created_at":     nil,
			"updated_at":     nil,
		}
		if createdAt.Valid {
			item["created_at"] = createdAt.Time
		}
		if updatedAt.Valid {
			item["updated_at"] = updatedAt.Time
		}
		list = append(list, item)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *APIServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireGETWithDB(w, r) {
		return
	}

	engagementID := strings.TrimSpace(r.URL.Query().Get("engagement_id"))

	query := `SELECT id, COALESCE(engagement_id::text, ''), actor, action, COALESCE(details, '{}'::jsonb), created_at
		FROM audit_logs`
	var args []interface{}
	if engagementID != "" {
		query += " WHERE engagement_id::text = $1"
		args = append(args, engagementID)
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	list := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id, engID, actor, action string
		var details []byte
		var createdAt sql.NullTime
		if err := rows.Scan(&id, &engID, &actor, &action, &details, &createdAt); err != nil {
			log.Printf("[API] audit_logs row scan error: %v", err)
			continue
		}
		item := map[string]interface{}{
			"id":            id,
			"engagement_id": engID,
			"actor":         actor,
			"action":        action,
			"details":       decodeJSONObject(details),
			"created_at":    nil,
		}
		if createdAt.Valid {
			item["created_at"] = createdAt.Time
		}
		list = append(list, item)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *APIServer) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || strings.TrimSpace(req.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "Invalid target domain")
		return
	}
	target := strings.TrimSpace(req.Target)

	if !s.hasDB() {
		writeJSONError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "QUEUED",
		"target":  target,
		"message": "Autonomous ARTEX-Pro pipeline dispatched in background Goroutine",
	})

	// Dispatch background Goroutine with panic recovery
	go func(t string) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[-] [API] Recovered from background mission panic: %v", rec)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		_, _ = s.orchestrator.RunAutonomousMission(ctx, t)
	}(target)
}
