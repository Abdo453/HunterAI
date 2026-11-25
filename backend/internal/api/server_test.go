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

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("OPTIONS %s: expected 200, got %d", path, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("OPTIONS %s: expected Access-Control-Allow-Origin '*', got %q", path, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") || !strings.Contains(got, "POST") {
			t.Fatalf("OPTIONS %s: unexpected Access-Control-Allow-Methods %q", path, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") {
			t.Fatalf("OPTIONS %s: unexpected Access-Control-Allow-Headers %q", path, got)
		}
	}

	// Non-OPTIONS requests must also carry CORS headers
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("GET /api/v1/health: expected Access-Control-Allow-Origin '*', got %q", got)
	}
}

func TestScanMethodAndPayloadValidation(t *testing.T) {
	scanDispatched := make(chan struct{}, 1)
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

	// Reject unsupported methods
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/scan", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /api/v1/scan: expected 405, got %d", method, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("%s /api/v1/scan: expected CORS header on 405, got %q", method, got)
		}
	}

	// Reject malformed JSON and empty target
	for _, body := range []string{`{invalid`, `{}`, `{"target": "   "}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST /api/v1/scan (%s): expected 400, got %d", body, rec.Code)
		}
	}

	// Reject scan when DB is nil instead of panicking in background goroutine
	nilSrv := NewAPIServer(nil, 0)
	nilReq := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.com"}`))
	nilRec := httptest.NewRecorder()
	nilSrv.Handler().ServeHTTP(nilRec, nilReq)
	if nilRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/v1/scan with nil DB: expected 503, got %d", nilRec.Code)
	}

	// Accept valid POST /api/v1/scan
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":" example.com "}`))
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
