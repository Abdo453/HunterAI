package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"artex-pro/internal/agent"
	"artex-pro/internal/database"
)

// APIServer exposes the ARTEX-Pro HTTP REST API backed by PostgreSQL.
type APIServer struct {
	db           *database.DB
	orchestrator *agent.Orchestrator
	port         int
	apiToken     string
}

func generateRandomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("failed to generate CSPRNG API token: %v", err))
	}
	return hex.EncodeToString(buf)
}

func resolveConfiguredToken(fallback string) string {
	if t := strings.TrimSpace(os.Getenv("ARTEX_API_TOKEN")); t != "" {
		return t
	}
	if t := strings.TrimSpace(os.Getenv("HUNTER_API_TOKEN")); t != "" {
		return t
	}
	return strings.TrimSpace(fallback)
}

// NewAPIServer constructs an APIServer bound to the provided database handle and TCP port.
func NewAPIServer(db *database.DB, port int) *APIServer {
	tok := resolveConfiguredToken("")
	if tok == "" {
		tok = generateRandomToken()
	}
	return &APIServer{
		db:           db,
		orchestrator: agent.NewOrchestrator(db),
		port:         port,
		apiToken:     tok,
	}
}

// APIToken returns the active local bearer token enforced on mutation/scan endpoints.
func (s *APIServer) APIToken() string {
	return resolveConfiguredToken(s.apiToken)
}

// ResolveBindAddr returns the bind address (defaulting to loopback 127.0.0.1:<port>, configurable via ARTEX_BIND_ADDR).
func (s *APIServer) ResolveBindAddr() string {
	if raw := strings.TrimSpace(os.Getenv("ARTEX_BIND_ADDR")); raw != "" {
		if strings.Contains(raw, ":") {
			return raw
		}
		return net.JoinHostPort(raw, strconv.Itoa(s.port))
	}
	return fmt.Sprintf("127.0.0.1:%d", s.port)
}

func constantTimeTokenEqual(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	pBytes := []byte(provided)
	eBytes := []byte(expected)
	if len(pBytes) != len(eBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(pBytes, eBytes) == 1
}

func extractBearerToken(r *http.Request) string {
	if hdr := strings.TrimSpace(r.Header.Get("Authorization")); hdr != "" {
		parts := strings.SplitN(hdr, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-Hunter-Token"))
}

func (s *APIServer) requireBearerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := s.APIToken()
		provided := extractBearerToken(r)
		if !constantTimeTokenEqual(provided, expected) {
			writeJSONError(w, http.StatusUnauthorized, "Valid Authorization: Bearer or X-Hunter-Token required")
			return
		}
		next(w, r)
	}
}

var defaultAllowedCORSOrigins = []string{
	"http://127.0.0.1:3000",
	"http://localhost:3000",
	"http://127.0.0.1:8000",
	"http://localhost:8000",
}

func normalizeOrigin(origin string) string {
	trimmed := strings.TrimSpace(origin)
	if trimmed == "" || trimmed == "*" || strings.EqualFold(trimmed, "null") {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	if strings.Contains(u.Host, "*") {
		return ""
	}
	if u.Path != "" && u.Path != "/" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + strings.ToLower(u.Host)
}

func getAllowedCORSOrigins() map[string]struct{} {
	allowed := make(map[string]struct{})
	raw := strings.TrimSpace(os.Getenv("ARTEX_ALLOWED_ORIGINS"))
	var candidates []string
	if raw == "" {
		candidates = defaultAllowedCORSOrigins
	} else {
		for _, part := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				candidates = append(candidates, trimmed)
			}
		}
	}
	for _, c := range candidates {
		if norm := normalizeOrigin(c); norm != "" {
			allowed[norm] = struct{}{}
		}
	}
	return allowed
}

func isOriginAllowed(origin string) bool {
	norm := normalizeOrigin(origin)
	if norm == "" {
		return false
	}
	_, ok := getAllowedCORSOrigins()[norm]
	return ok
}

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowed := false
		if origin != "" {
			allowed = isOriginAllowed(origin)
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hunter-Token")
			}
		}
		if r.Method == http.MethodOptions {
			if origin != "" && !allowed {
				writeJSONError(w, http.StatusForbidden, "Origin not allowed by CORS policy")
				return
			}
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
	mux.HandleFunc("/api/v1/stats", enableCORS(s.requireBearerAuth(s.handleStats)))
	mux.HandleFunc("/api/v1/engagements", enableCORS(s.requireBearerAuth(s.handleEngagements)))
	mux.HandleFunc("/api/v1/assets", enableCORS(s.requireBearerAuth(s.handleAssets)))
	mux.HandleFunc("/api/v1/findings", enableCORS(s.requireBearerAuth(s.handleFindings)))
	mux.HandleFunc("/api/v1/tasks", enableCORS(s.requireBearerAuth(s.handleTasks)))
	mux.HandleFunc("/api/v1/audit", enableCORS(s.requireBearerAuth(s.handleAudit)))
	mux.HandleFunc("/api/v1/scan", enableCORS(s.requireBearerAuth(s.handleScan)))

	return mux
}

// Start begins serving the ARTEX-Pro REST API on the configured loopback/ARTEX_BIND_ADDR address.
func (s *APIServer) Start() error {
	addr := s.ResolveBindAddr()
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

func allowLocalScanEnabled() bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_ALLOW_LOCAL_SCAN")))
	switch val {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

var hardBlockedMetadataHosts = map[string]struct{}{
	"metadata.google.internal": {},
	"metadata.internal":        {},
	"instance-data":            {},
	"100.100.100.200":          {},
	"fd00:ec2::254":            {},
}

func parseLegacyIPv4(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return netip.Addr{}, false
		}
		v, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		vals[i] = v
	}

	var ip32 uint32
	switch len(vals) {
	case 1:
		ip32 = uint32(vals[0])
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return netip.Addr{}, false
		}
		ip32 = uint32(vals[0]<<24) | uint32(vals[1])
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return netip.Addr{}, false
		}
		ip32 = uint32(vals[0]<<24) | uint32(vals[1]<<16) | uint32(vals[2])
	case 4:
		for _, v := range vals {
			if v > 0xff {
				return netip.Addr{}, false
			}
		}
		ip32 = uint32(vals[0]<<24) | uint32(vals[1]<<16) | uint32(vals[2]<<8) | uint32(vals[3])
	}

	addr := netip.AddrFrom4([4]byte{
		byte(ip32 >> 24),
		byte(ip32 >> 16),
		byte(ip32 >> 8),
		byte(ip32),
	})
	return addr, true
}

func parseFlexibleIP(host string) (netip.Addr, bool) {
	clean := strings.TrimSpace(host)
	clean = strings.TrimPrefix(clean, "[")
	clean = strings.TrimSuffix(clean, "]")
	if zoneIdx := strings.IndexByte(clean, '%'); zoneIdx != -1 {
		clean = clean[:zoneIdx]
	}
	if clean == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(clean); err == nil {
		return addr.Unmap(), true
	}
	return parseLegacyIPv4(clean)
}

func extractTargetHost(trimmed string) (string, int, string) {
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" || u.User != nil {
			return "", http.StatusBadRequest, "Invalid target URL authority"
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", http.StatusBadRequest, "Invalid target URL scheme: only http and https are permitted"
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host == "" {
			return "", http.StatusBadRequest, "Invalid target domain"
		}
		return host, 0, ""
	}

	// Reject opaque non-HTTP schemes like file:/etc/passwd or javascript:alert(1)
	if colonIdx := strings.IndexByte(trimmed, ':'); colonIdx > 0 && !strings.HasPrefix(trimmed, "[") {
		rest := trimmed[colonIdx+1:]
		if !strings.Contains(rest, ":") {
			hostPart := trimmed[:colonIdx]
			portDigits := strings.SplitN(rest, "/", 2)[0]
			if portDigits == "" {
				return "", http.StatusBadRequest, "Invalid target URL scheme"
			}
			for _, r := range portDigits {
				if r < '0' || r > '9' {
					return "", http.StatusBadRequest, "Invalid target URL scheme"
				}
			}
			host := strings.TrimSuffix(strings.ToLower(hostPart), ".")
			if host == "" {
				return "", http.StatusBadRequest, "Invalid target domain"
			}
			return host, 0, ""
		}
	}

	// Bare IPv6 literal (e.g., ::1 or [::1]:8080)
	if strings.HasPrefix(trimmed, "[") {
		end := strings.IndexByte(trimmed, ']')
		if end == -1 {
			return "", http.StatusBadRequest, "Invalid bracketed target host"
		}
		return strings.TrimSuffix(strings.ToLower(trimmed[1:end]), "."), 0, ""
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return strings.ToLower(addr.String()), 0, ""
	}

	hostPart := strings.SplitN(trimmed, "/", 2)[0]
	hostPart = strings.TrimSuffix(strings.ToLower(hostPart), ".")
	if hostPart == "" {
		return "", http.StatusBadRequest, "Invalid target domain"
	}
	return hostPart, 0, ""
}

func classifyTargetAddr(addr netip.Addr, allowLocal bool) (int, string) {
	addr = addr.Unmap().WithZone("")

	// Non-overridable link-local/metadata, unspecified, multicast, and reserved ranges.
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return http.StatusForbidden, fmt.Sprintf("Target IP %s belongs to a non-overridable restricted range", addr)
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 0 || b[0] >= 240 || (b[0] == 169 && b[1] == 254) {
			return http.StatusForbidden, fmt.Sprintf("Target IP %s belongs to a non-overridable restricted subnet", addr)
		}
		// 100.64.0.0/10 (CGNAT) and 100.100.100.200 (Alibaba cloud metadata)
		if b[0] == 100 && b[1] == 100 && b[2] == 100 && b[3] == 200 {
			return http.StatusForbidden, fmt.Sprintf("Target IP %s is a non-overridable cloud metadata address", addr)
		}
		if !allowLocal && b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return http.StatusForbidden, fmt.Sprintf("Target IP %s belongs to internal CGNAT range", addr)
		}
	} else {
		if _, isMeta := hardBlockedMetadataHosts[strings.ToLower(addr.String())]; isMeta {
			return http.StatusForbidden, fmt.Sprintf("Target IP %s is a non-overridable cloud metadata address", addr)
		}
		// Block NAT64 well-known prefix 64:ff9b::/96 wrapping IPv4 private/metadata addresses
		b16 := addr.As16()
		if b16[0] == 0x00 && b16[1] == 0x64 && b16[2] == 0xff && b16[3] == 0x9b &&
			b16[4] == 0 && b16[5] == 0 && b16[6] == 0 && b16[7] == 0 &&
			b16[8] == 0 && b16[9] == 0 && b16[10] == 0 && b16[11] == 0 {
			embedded := netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]})
			if st, rsn := classifyTargetAddr(embedded, allowLocal); st != 0 {
				return st, rsn
			}
		}
	}

	if !allowLocal && (addr.IsLoopback() || addr.IsPrivate()) {
		return http.StatusForbidden, fmt.Sprintf("Target IP %s is a private or loopback destination (set ARTEX_ALLOW_LOCAL_SCAN=1 for explicit local lab testing)", addr)
	}
	return 0, ""
}

func validateScanTarget(ctx context.Context, rawTarget string) (string, int, string) {
	trimmed := strings.TrimSpace(rawTarget)
	if trimmed == "" {
		return "", http.StatusBadRequest, "Invalid target domain"
	}
	if len(trimmed) > 2048 {
		return "", http.StatusBadRequest, "Target exceeds maximum allowed length"
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", http.StatusBadRequest, "Invalid target: whitespace and control characters are not permitted"
		}
	}
	if strings.ContainsAny(trimmed, ";|&$`()<>\\'\"{}*?~!") {
		return "", http.StatusBadRequest, "Invalid target: disallowed shell metacharacters"
	}

	host, status, reason := extractTargetHost(trimmed)
	if status != 0 {
		return "", status, reason
	}

	if _, blocked := hardBlockedMetadataHosts[host]; blocked {
		return "", http.StatusForbidden, fmt.Sprintf("Target host %q is a non-overridable metadata destination", host)
	}

	allowLocal := allowLocalScanEnabled()
	if !allowLocal && (host == "localhost" || host == "localhost.localdomain" || strings.HasSuffix(host, ".localhost")) {
		return "", http.StatusForbidden, fmt.Sprintf("Target host %q is a restricted loopback destination", host)
	}

	if addr, isIP := parseFlexibleIP(host); isIP {
		if status, reason := classifyTargetAddr(addr, allowLocal); status != 0 {
			return "", status, reason
		}
		return trimmed, 0, ""
	}

	if strings.ContainsAny(host, "[]") || strings.Contains(host, "..") || strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return "", http.StatusBadRequest, "Invalid target domain format"
	}

	// Opportunistically check resolved IPs without breaking offline test runs.
	dnsCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if addrs, err := net.DefaultResolver.LookupNetIP(dnsCtx, "ip", host); err == nil {
		for _, addr := range addrs {
			if status, reason := classifyTargetAddr(addr, allowLocal); status != 0 {
				return "", status, reason
			}
		}
	}

	return trimmed, 0, ""
}

func (s *APIServer) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid target domain")
		return
	}
	target, status, reason := validateScanTarget(r.Context(), req.Target)
	if status != 0 {
		writeJSONError(w, status, reason)
		return
	}

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
		if _, err := s.orchestrator.RunAutonomousMission(ctx, t); err != nil {
			log.Printf("[-] [API] Background mission failed for %q: %v", t, err)
		}
	}(target)
}
