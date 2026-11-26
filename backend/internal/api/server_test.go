package api

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"artex-pro/internal/database"
)

type recordedQuery struct {
	query string
	args  []driver.NamedValue
}

type stubDriverState struct {
	mu           sync.Mutex
	pingErr      error
	execErr      error
	queryHandler func(query string, args []driver.NamedValue) (driver.Rows, error)
	queries      []recordedQuery
	execs        []string
}

func (s *stubDriverState) recordQuery(query string, args []driver.NamedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make([]driver.NamedValue, len(args))
	copy(copied, args)
	s.queries = append(s.queries, recordedQuery{query: query, args: copied})
}

func (s *stubDriverState) lastQuery() (recordedQuery, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queries) == 0 {
		return recordedQuery{}, false
	}
	return s.queries[len(s.queries)-1], true
}

func (s *stubDriverState) recordExec(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
}

type stubConnector struct {
	state *stubDriverState
}

func (c *stubConnector) Connect(context.Context) (driver.Conn, error) {
	return &stubConn{state: c.state}, nil
}

func (c *stubConnector) Driver() driver.Driver {
	return stubDriver{}
}

type stubDriver struct{}

func (stubDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("not supported")
}

type stubConn struct {
	state *stubDriverState
}

func (c *stubConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not implemented in stub")
}

func (c *stubConn) Close() error {
	return nil
}

func (c *stubConn) Begin() (driver.Tx, error) {
	return stubTx{}, nil
}

func (c *stubConn) Ping(context.Context) error {
	c.state.mu.Lock()
	err := c.state.pingErr
	c.state.mu.Unlock()
	return err
}

func (c *stubConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.state.recordExec(query)
	c.state.mu.Lock()
	err := c.state.execErr
	c.state.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

func (c *stubConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.recordQuery(query, args)
	if c.state.queryHandler != nil {
		return c.state.queryHandler(query, args)
	}
	return &stubRows{}, nil
}

type stubTx struct{}

func (stubTx) Commit() error   { return nil }
func (stubTx) Rollback() error { return nil }

type stubRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (r *stubRows) Columns() []string {
	if len(r.cols) == 0 {
		return []string{"col"}
	}
	return r.cols
}

func (r *stubRows) Close() error { return nil }

func (r *stubRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

func newStubDB(t *testing.T, state *stubDriverState) *database.DB {
	t.Helper()
	if state == nil {
		state = &stubDriverState{}
	}
	sqlDB := sql.OpenDB(&stubConnector{state: state})
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})
	return &database.DB{DB: sqlDB}
}

func TestCORSHeaders(t *testing.T) {
	state := &stubDriverState{}
	srv := NewAPIServer(newStubDB(t, state), 0)
	handler := srv.Handler()

	paths := []string{
		"/api/v1/health",
		"/api/v1/stats",
		"/api/v1/engagements",
		"/api/v1/assets",
		"/api/v1/findings",
		"/api/v1/tasks",
		"/api/v1/audit",
		"/api/v1/scan",
	}

	defaultOrigins := []string{
		"http://127.0.0.1:3000",
		"http://localhost:3000",
		"http://127.0.0.1:8000",
		"http://localhost:8000",
	}

	for _, origin := range defaultOrigins {
		for _, path := range paths {
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("OPTIONS %s (origin %s): expected 200, got %d", path, origin, rec.Code)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
				t.Fatalf("OPTIONS %s: expected Access-Control-Allow-Origin %q, got %q", path, origin, got)
			}
			if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
				t.Fatalf("OPTIONS %s: expected Vary to contain Origin, got %q", path, got)
			}
			if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") || !strings.Contains(got, "POST") {
				t.Fatalf("OPTIONS %s: unexpected Access-Control-Allow-Methods %q", path, got)
			}
			if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") {
				t.Fatalf("OPTIONS %s: unexpected Access-Control-Allow-Headers %q", path, got)
			}
		}
	}

	// Non-OPTIONS allowed requests echo exact origin and Vary: Origin
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "http://127.0.0.1:3000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:3000" {
		t.Fatalf("GET /api/v1/health: expected echoed origin, got %q", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Fatalf("GET /api/v1/health: expected Vary: Origin, got %q", got)
	}

	// Disallowed origins must never receive wildcard or reflected ACAO
	badPreflight := httptest.NewRequest(http.MethodOptions, "/api/v1/scan", nil)
	badPreflight.Header.Set("Origin", "https://evil.example.com")
	badPreflightRec := httptest.NewRecorder()
	handler.ServeHTTP(badPreflightRec, badPreflight)
	if badPreflightRec.Code != http.StatusForbidden {
		t.Fatalf("OPTIONS /api/v1/scan disallowed origin: expected 403, got %d", badPreflightRec.Code)
	}
	if got := badPreflightRec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("OPTIONS /api/v1/scan disallowed origin: expected empty ACAO, got %q", got)
	}

	badGet := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	badGet.Header.Set("Origin", "https://evil.example.com")
	badGetRec := httptest.NewRecorder()
	handler.ServeHTTP(badGetRec, badGet)
	if got := badGetRec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("GET /api/v1/health disallowed origin: expected empty ACAO, got %q", got)
	}

	// Requests without Origin must never fall back to wildcard '*'
	noOrigin := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	noOriginRec := httptest.NewRecorder()
	handler.ServeHTTP(noOriginRec, noOrigin)
	if got := noOriginRec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Fatalf("GET /api/v1/health without Origin: must never emit wildcard '*'")
	}

	// Custom ARTEX_ALLOWED_ORIGINS overrides default list
	t.Setenv("ARTEX_ALLOWED_ORIGINS", "https://panel.internal:8443, https://console.example.com/")
	customAllowed := httptest.NewRequest(http.MethodOptions, "/api/v1/scan", nil)
	customAllowed.Header.Set("Origin", "https://console.example.com")
	customAllowedRec := httptest.NewRecorder()
	handler.ServeHTTP(customAllowedRec, customAllowed)
	if customAllowedRec.Code != http.StatusOK || customAllowedRec.Header().Get("Access-Control-Allow-Origin") != "https://console.example.com" {
		t.Fatalf("custom allowed origin failed: code=%d acao=%q", customAllowedRec.Code, customAllowedRec.Header().Get("Access-Control-Allow-Origin"))
	}

	customDenied := httptest.NewRequest(http.MethodOptions, "/api/v1/scan", nil)
	customDenied.Header.Set("Origin", "http://127.0.0.1:3000")
	customDeniedRec := httptest.NewRecorder()
	handler.ServeHTTP(customDeniedRec, customDenied)
	if customDeniedRec.Code != http.StatusForbidden {
		t.Fatalf("default origin should be rejected when ARTEX_ALLOWED_ORIGINS overrides list, got %d", customDeniedRec.Code)
	}
}

func TestScanMethodAndPayloadValidation(t *testing.T) {
	scanDispatched := make(chan struct{}, 2)
	state := &stubDriverState{
		queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
			if strings.Contains(query, "INSERT INTO engagements") {
				select {
				case scanDispatched <- struct{}{}:
				default:
				}
				return nil, errors.New("stop stub background scan")
			}
			return &stubRows{}, nil
		},
	}
	srv := NewAPIServer(newStubDB(t, state), 0)
	handler := srv.Handler()
	authHeader := "Bearer " + srv.APIToken()

	// Unauthenticated POST /api/v1/scan must fail closed with 401
	unauthReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
	unauthRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /api/v1/scan: expected 401, got %d", unauthRec.Code)
	}

	// Wrong bearer token must fail closed with 401
	badTokReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
	badTokReq.Header.Set("Authorization", "Bearer wrong-token-value")
	badTokRec := httptest.NewRecorder()
	handler.ServeHTTP(badTokRec, badTokReq)
	if badTokRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer token POST /api/v1/scan: expected 401, got %d", badTokRec.Code)
	}

	// Reject unsupported methods and echo CORS only for allowed Origin
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/scan", nil)
		req.Header.Set("Origin", "http://127.0.0.1:3000")
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /api/v1/scan: expected 405, got %d", method, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:3000" {
			t.Fatalf("%s /api/v1/scan: expected echoed CORS header on 405, got %q", method, got)
		}
	}

	// Reject malformed JSON, empty target, shell metacharacters, control chars, and non-HTTP schemes with 400
	badInputs := []string{
		`{invalid`,
		`{}`,
		`{"target": "   "}`,
		`{"target": "example.com; id"}`,
		`{"target": "example.com && whoami"}`,
		`{"target": "example.com | id"}`,
		`{"target": "$(cat /etc/passwd)"}`,
		`{"target": "example.com` + "`id`" + `"}`,
		`{"target": "example.com\nid"}`,
		`{"target": "example.com\u0000"}`,
		`{"target": "file:///etc/passwd"}`,
		`{"target": "gopher://127.0.0.1:6379/_INFO"}`,
	}
	for _, body := range badInputs {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST /api/v1/scan (%s): expected 400, got %d (body: %s)", body, rec.Code, rec.Body.String())
		}
	}

	// Non-overridable cloud metadata, link-local, and unspecified targets stay 403 in both modes
	hardBlockedTargets := []string{
		"169.254.169.254",
		"http://169.254.169.254/latest/meta-data/",
		"[::ffff:169.254.169.254]",
		"[64:ff9b::169.254.169.254]",
		"2852039166",
		"0xa9fea9fe",
		"metadata.google.internal",
		"metadata.internal",
		"100.100.100.200",
		"fd00:ec2::254",
		"0.0.0.0",
	}
	localAndPrivateTargets := []string{
		"127.0.0.1",
		"http://127.0.0.1:8080",
		"localhost",
		"http://localhost:3000",
		"::1",
		"[::ffff:127.0.0.1]",
		"[fc00::1]",
		"2130706433",
		"0x7f000001",
		"10.0.0.1",
		"192.168.1.10",
		"172.16.0.5",
	}

	// Default mode (ARTEX_ALLOW_LOCAL_SCAN unset): fails closed for BOTH private/loopback IPv4/IPv6 and cloud metadata
	t.Run("default fails closed on private/loopback and cloud metadata", func(t *testing.T) {
		t.Setenv("ARTEX_ALLOW_LOCAL_SCAN", "")

		for _, target := range append(append([]string(nil), localAndPrivateTargets...), hardBlockedTargets...) {
			payload := `{"target":"` + target + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(payload))
			req.Header.Set("Authorization", authHeader)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("POST /api/v1/scan (%s) default mode: expected 403, got %d (body: %s)", target, rec.Code, rec.Body.String())
			}
		}

		pubReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
		pubReq.Header.Set("Authorization", authHeader)
		pubRec := httptest.NewRecorder()
		handler.ServeHTTP(pubRec, pubReq)
		if pubRec.Code != http.StatusAccepted {
			t.Fatalf("example.com default mode expected 202, got %d (body: %s)", pubRec.Code, pubRec.Body.String())
		}
		select {
		case <-scanDispatched:
		case <-time.After(2 * time.Second):
			t.Fatalf("expected public scan goroutine to invoke orchestrator")
		}
	})

	// Explicit test override flag (ARTEX_ALLOW_LOCAL_SCAN=1) allows loopback/private targets while STILL blocking cloud metadata
	t.Run("explicit ARTEX_ALLOW_LOCAL_SCAN=1 allows local labs while blocking cloud metadata", func(t *testing.T) {
		t.Setenv("ARTEX_ALLOW_LOCAL_SCAN", "1")

		for _, target := range hardBlockedTargets {
			payload := `{"target":"` + target + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(payload))
			req.Header.Set("Authorization", authHeader)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("POST /api/v1/scan (%s) with ARTEX_ALLOW_LOCAL_SCAN=1: expected 403, got %d (body: %s)", target, rec.Code, rec.Body.String())
			}
		}

		for _, target := range localAndPrivateTargets {
			payload := `{"target":"` + target + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(payload))
			req.Header.Set("Authorization", authHeader)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("POST /api/v1/scan (%s) with ARTEX_ALLOW_LOCAL_SCAN=1: expected 202, got %d (body: %s)", target, rec.Code, rec.Body.String())
			}
			select {
			case <-scanDispatched:
			case <-time.After(2 * time.Second):
				t.Fatalf("expected opt-in local scan goroutine to invoke orchestrator for %s", target)
			}
		}
	})

	// Reject scan when DB is nil instead of panicking in background goroutine
	nilSrv := NewAPIServer(nil, 0)
	nilReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
	nilReq.Header.Set("Authorization", "Bearer "+nilSrv.APIToken())
	nilRec := httptest.NewRecorder()
	nilSrv.Handler().ServeHTTP(nilRec, nilReq)
	if nilRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/v1/scan with nil DB: expected 503, got %d", nilRec.Code)
	}

	// Accept valid POST /api/v1/scan
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":" example.com "}`))
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/v1/scan valid: expected 202, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode scan response: %v", err)
	}
	if payload["status"] != "QUEUED" || payload["target"] != "example.com" {
		t.Fatalf("unexpected scan payload: %+v", payload)
	}

	select {
	case <-scanDispatched:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected background scan goroutine to invoke orchestrator")
	}
}

func TestHealthCheck(t *testing.T) {
	t.Run("nil database reports disconnected and 503", func(t *testing.T) {
		srv := NewAPIServer(nil, 0)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if body["status"] != "degraded" || body["database"] != "disconnected" {
			t.Fatalf("unexpected health body: %+v", body)
		}
		if strings.Contains(rec.Body.String(), "PostgreSQL 16+") {
			t.Fatalf("health must not hardcode PostgreSQL 16+: %s", rec.Body.String())
		}
	})

	t.Run("ping failure reports disconnected and 503", func(t *testing.T) {
		state := &stubDriverState{pingErr: errors.New("connection refused")}
		srv := NewAPIServer(newStubDB(t, state), 0)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if body["status"] != "degraded" || body["database"] != "disconnected" {
			t.Fatalf("unexpected health body: %+v", body)
		}
		if !strings.Contains(fmtError(body["error"]), "connection refused") {
			t.Fatalf("expected ping error detail in body: %+v", body)
		}
	})

	t.Run("ping success reports connected and 200", func(t *testing.T) {
		state := &stubDriverState{}
		srv := NewAPIServer(newStubDB(t, state), 0)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if body["status"] != "healthy" || body["database"] != "connected" {
			t.Fatalf("unexpected health body: %+v", body)
		}
	})
}

func TestNilDBSafety(t *testing.T) {
	srv := NewAPIServer(nil, 0)
	handler := srv.Handler()

	endpoints := []string{
		"/api/v1/health",
		"/api/v1/stats",
		"/api/v1/engagements",
		"/api/v1/assets",
		"/api/v1/findings",
		"/api/v1/tasks",
		"/api/v1/audit",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		if ep != "/api/v1/health" {
			req.Header.Set("Authorization", "Bearer "+srv.APIToken())
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET %s with nil DB: expected 503, got %d", ep, rec.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s with nil DB: invalid json: %v", ep, err)
		}
	}

	// Verify database.Migrate also handles nil safely without panicking
	var nilDB *database.DB
	if err := nilDB.Migrate(context.Background()); err == nil {
		t.Fatalf("expected error from nilDB.Migrate")
	}
}

func TestEmptySliceSerialization(t *testing.T) {
	state := &stubDriverState{
		queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
			return &stubRows{}, nil
		},
	}
	srv := NewAPIServer(newStubDB(t, state), 0)
	handler := srv.Handler()

	listEndpoints := []string{
		"/api/v1/engagements",
		"/api/v1/assets",
		"/api/v1/findings",
		"/api/v1/tasks",
		"/api/v1/audit",
	}

	for _, ep := range listEndpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("Authorization", "Bearer "+srv.APIToken())
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: expected 200, got %d (%s)", ep, rec.Code, rec.Body.String())
		}
		trimmed := bytes.TrimSpace(rec.Body.Bytes())
		if string(trimmed) != "[]" {
			t.Fatalf("GET %s: expected empty JSON array [], got %q", ep, string(trimmed))
		}
	}
}

func TestSchemaAlignedQueriesAndFilters(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	t.Run("engagements uses started_at", func(t *testing.T) {
		state := &stubDriverState{
			queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				return &stubRows{
					cols: []string{"id", "code", "target_url", "authorized_scope", "status", "started_at", "finished_at"},
					data: [][]driver.Value{
						{"eng-1", "ENG-1234", "https://example.com", "example.com", "ACTIVE", now, nil},
					},
				}, nil
			},
		}
		srv := NewAPIServer(newStubDB(t, state), 0)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil)
		req.Header.Set("Authorization", "Bearer "+srv.APIToken())
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		q, ok := state.lastQuery()
		if !ok {
			t.Fatalf("expected SQL query to be recorded")
		}
		if !strings.Contains(q.query, "started_at") || strings.Contains(q.query, "created_at") {
			t.Fatalf("engagements query drifted from schema: %s", q.query)
		}
		var rows []map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if len(rows) != 1 || rows[0]["started_at"] == nil || rows[0]["code"] != "ENG-1234" {
			t.Fatalf("unexpected engagement rows: %+v", rows)
		}
	})

	t.Run("assets uses first_seen and engagement_id join filter", func(t *testing.T) {
		state := &stubDriverState{
			queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				return &stubRows{
					cols: []string{"id", "target_id", "kind", "value", "attributes", "first_seen"},
					data: [][]driver.Value{
						{"asset-1", "tgt-1", "SUBDOMAIN", "api.example.com", []byte(""), now},
					},
				}, nil
			},
		}
		srv := NewAPIServer(newStubDB(t, state), 0)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets?target=api&engagement_id=eng-99", nil)
		req.Header.Set("Authorization", "Bearer "+srv.APIToken())
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		q, ok := state.lastQuery()
		if !ok {
			t.Fatalf("expected SQL query to be recorded")
		}
		if !strings.Contains(q.query, "a.first_seen") || strings.Contains(q.query, "asset_nodes.created_at") {
			t.Fatalf("assets query drifted from schema: %s", q.query)
		}
		if !strings.Contains(q.query, "t.engagement_id::text") {
			t.Fatalf("assets query missing engagement_id filter: %s", q.query)
		}
		if len(q.args) != 3 || q.args[0].Value != "%api%" || q.args[1].Value != "api" || q.args[2].Value != "eng-99" {
			t.Fatalf("unexpected assets query args: %+v", q.args)
		}
		var rows []map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if len(rows) != 1 || rows[0]["first_seen"] == nil || rows[0]["attributes"] == nil {
			t.Fatalf("unexpected asset rows: %+v", rows)
		}
	})

	t.Run("findings supports engagement_id filter and cvss_score/endpoint", func(t *testing.T) {
		state := &stubDriverState{
			queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				return &stubRows{
					cols: []string{"id", "engagement_id", "target_id", "title", "vuln_class", "severity", "cvss_score", "confidence", "endpoint", "evidence", "status", "created_at"},
					data: [][]driver.Value{
						{"f-1", "eng-99", "tgt-1", "Exposed Admin", "admin-panel", "high", 8.0, 0.9, "https://api.example.com/admin", "HTTP 200", "TRIAGED", now},
					},
				}, nil
			},
		}
		srv := NewAPIServer(newStubDB(t, state), 0)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings?engagement_id=eng-99", nil)
		req.Header.Set("Authorization", "Bearer "+srv.APIToken())
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		q, ok := state.lastQuery()
		if !ok {
			t.Fatalf("expected SQL query to be recorded")
		}
		if !strings.Contains(q.query, "engagement_id::text = $1") || len(q.args) != 1 || q.args[0].Value != "eng-99" {
			t.Fatalf("findings query missing engagement_id filter: %s args=%+v", q.query, q.args)
		}
		var rows []map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatalf("invalid json: %v", err)
		}
		if len(rows) != 1 || rows[0]["cvss_score"] != 8.0 || rows[0]["endpoint"] != "https://api.example.com/admin" {
			t.Fatalf("unexpected findings rows: %+v", rows)
		}
	})

	t.Run("tasks and audit support optional engagement_id filter", func(t *testing.T) {
		state := &stubDriverState{
			queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				if strings.Contains(query, "FROM tasks") {
					return &stubRows{
						cols: []string{"id", "engagement_id", "agent_role", "title", "status", "priority", "input_context", "output_summary", "created_at", "updated_at"},
						data: [][]driver.Value{
							{"t-1", "eng-99", "RECON", "Passive Subdomain Enumeration", "COMPLETED", int64(9), []byte(`{"domain":"example.com"}`), []byte(`{}`), now, now},
						},
					}, nil
				}
				return &stubRows{
					cols: []string{"id", "engagement_id", "actor", "action", "details", "created_at"},
					data: [][]driver.Value{
						{"a-1", "eng-99", "ReconWorker", "ENUMERATED", []byte(`{"count":12}`), now},
					},
				}, nil
			},
		}
		srv := NewAPIServer(newStubDB(t, state), 0)

		// Tasks
		reqTasks := httptest.NewRequest(http.MethodGet, "/api/v1/tasks?engagement_id=eng-99", nil)
		reqTasks.Header.Set("Authorization", "Bearer "+srv.APIToken())
		recTasks := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recTasks, reqTasks)
		if recTasks.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/tasks: expected 200, got %d", recTasks.Code)
		}
		qTasks, _ := state.lastQuery()
		if !strings.Contains(qTasks.query, "engagement_id::text = $1") || len(qTasks.args) != 1 || qTasks.args[0].Value != "eng-99" {
			t.Fatalf("tasks query missing engagement_id filter: %s", qTasks.query)
		}

		// Audit
		reqAudit := httptest.NewRequest(http.MethodGet, "/api/v1/audit?engagement_id=eng-99", nil)
		reqAudit.Header.Set("Authorization", "Bearer "+srv.APIToken())
		recAudit := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recAudit, reqAudit)
		if recAudit.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/audit: expected 200, got %d", recAudit.Code)
		}
		qAudit, _ := state.lastQuery()
		if !strings.Contains(qAudit.query, "engagement_id::text = $1") || len(qAudit.args) != 1 || qAudit.args[0].Value != "eng-99" {
			t.Fatalf("audit query missing engagement_id filter: %s", qAudit.query)
		}
	})

	t.Run("migrate executes idempotent schema and additive migrations", func(t *testing.T) {
		state := &stubDriverState{}
		db := newStubDB(t, state)
		if err := db.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate failed: %v", err)
		}
		if len(state.execs) < 2 {
			t.Fatalf("expected schema + additive migration execs, got %d", len(state.execs))
		}
		if !strings.Contains(state.execs[0], "CREATE TABLE IF NOT EXISTS engagements") {
			t.Fatalf("expected first exec to contain schema DDL")
		}
	})
}

func fmtError(v interface{}) string {
	s, _ := v.(string)
	return s
}

func TestBindAddrAndAuthAndSSLHardening(t *testing.T) {
	t.Run("default bind address is loopback 127.0.0.1 and respects ARTEX_BIND_ADDR", func(t *testing.T) {
		t.Setenv("ARTEX_BIND_ADDR", "")
		srv := NewAPIServer(nil, 7071)
		if got := srv.ResolveBindAddr(); got != "127.0.0.1:7071" {
			t.Fatalf("expected default loopback bind 127.0.0.1:7071, got %q", got)
		}

		t.Setenv("ARTEX_BIND_ADDR", "127.0.0.1:9099")
		if got := srv.ResolveBindAddr(); got != "127.0.0.1:9099" {
			t.Fatalf("expected custom ARTEX_BIND_ADDR 127.0.0.1:9099, got %q", got)
		}
	})

	t.Run("accepts HUNTER_API_TOKEN and ARTEX_API_TOKEN via Bearer and X-Hunter-Token", func(t *testing.T) {
		t.Setenv("ARTEX_API_TOKEN", "")
		t.Setenv("HUNTER_API_TOKEN", "test-hunter-secret-token-32bytes-minimum")
		state := &stubDriverState{
			queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				if strings.Contains(query, "INSERT INTO engagements") {
					return nil, errors.New("stop stub background scan")
				}
				return &stubRows{}, nil
			},
		}
		srv := NewAPIServer(newStubDB(t, state), 7071)
		handler := srv.Handler()

		req1 := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
		req1.Header.Set("Authorization", "Bearer test-hunter-secret-token-32bytes-minimum")
		rec1 := httptest.NewRecorder()
		handler.ServeHTTP(rec1, req1)
		if rec1.Code != http.StatusAccepted {
			t.Fatalf("HUNTER_API_TOKEN Bearer expected 202, got %d", rec1.Code)
		}

		t.Setenv("ARTEX_API_TOKEN", "artex-dedicated-token-override")
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
		req2.Header.Set("X-Hunter-Token", "artex-dedicated-token-override")
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusAccepted {
			t.Fatalf("ARTEX_API_TOKEN X-Hunter-Token expected 202, got %d", rec2.Code)
		}

		// Old HUNTER_API_TOKEN must fail when ARTEX_API_TOKEN overrides it
		req3 := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
		req3.Header.Set("Authorization", "Bearer test-hunter-secret-token-32bytes-minimum")
		rec3 := httptest.NewRecorder()
		handler.ServeHTTP(rec3, req3)
		if rec3.Code != http.StatusUnauthorized {
			t.Fatalf("overridden token expected 401, got %d", rec3.Code)
		}
	})

	t.Run("read endpoints require bearer auth while /api/v1/health stays open", func(t *testing.T) {
		state := &stubDriverState{
			queryHandler: func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT COUNT(*)") {
					return &stubRows{cols: []string{"count"}, data: [][]driver.Value{{int64(0)}}}, nil
				}
				return &stubRows{}, nil
			},
		}
		srv := NewAPIServer(newStubDB(t, state), 7071)
		handler := srv.Handler()

		// Health stays publicly readable without bearer token
		healthReq := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		healthRec := httptest.NewRecorder()
		handler.ServeHTTP(healthRec, healthReq)
		if healthRec.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/health without auth expected 200, got %d", healthRec.Code)
		}

		// All data/state read routes fail closed 401 without valid bearer token
		protectedReads := []string{
			"/api/v1/stats",
			"/api/v1/engagements",
			"/api/v1/assets",
			"/api/v1/findings",
			"/api/v1/tasks",
			"/api/v1/audit",
		}
		for _, ep := range protectedReads {
			unauthReq := httptest.NewRequest(http.MethodGet, ep, nil)
			unauthRec := httptest.NewRecorder()
			handler.ServeHTTP(unauthRec, unauthReq)
			if unauthRec.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated GET %s expected 401, got %d", ep, unauthRec.Code)
			}

			authReq := httptest.NewRequest(http.MethodGet, ep, nil)
			authReq.Header.Set("Authorization", "Bearer "+srv.APIToken())
			authRec := httptest.NewRecorder()
			handler.ServeHTTP(authRec, authReq)
			if authRec.Code != http.StatusOK {
				t.Fatalf("authenticated GET %s expected 200, got %d (body=%s)", ep, authRec.Code, authRec.Body.String())
			}
		}
	})

	t.Run("wildcard origin in ARTEX_ALLOWED_ORIGINS is ignored", func(t *testing.T) {
		t.Setenv("ARTEX_ALLOWED_ORIGINS", "*, null")
		srv := NewAPIServer(nil, 7071)
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/scan", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when wildcard configured, got %d", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("must never echo wildcard ACAO, got %q", got)
		}
	})

	t.Run("database ResolveSSLMode defaults safely and validates input", func(t *testing.T) {
		t.Setenv("ARTEX_DB_SSLMODE", "")
		modeLocal, err := database.ResolveSSLMode("127.0.0.1", "")
		if err != nil || modeLocal != "disable" {
			t.Fatalf("loopback default sslmode expected disable, got %q err=%v", modeLocal, err)
		}
		modeRemote, err := database.ResolveSSLMode("db.internal.example.com", "")
		if err != nil || modeRemote != "require" {
			t.Fatalf("remote default sslmode expected require, got %q err=%v", modeRemote, err)
		}
		modeExplicit, err := database.ResolveSSLMode("127.0.0.1", "verify-full")
		if err != nil || modeExplicit != "verify-full" {
			t.Fatalf("explicit verify-full failed: got %q err=%v", modeExplicit, err)
		}
		if _, err := database.ResolveSSLMode("127.0.0.1", "invalid_mode"); err == nil {
			t.Fatalf("expected error for invalid sslmode")
		}
	})
}
