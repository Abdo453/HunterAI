package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"artex-pro/internal/arsenal"
	"artex-pro/internal/database"
)

type ReconWorker struct {
	db        *database.DB
	subfinder *arsenal.SubfinderRunner
}

func NewReconWorker(db *database.DB) *ReconWorker {
	return &ReconWorker{
		db:        db,
		subfinder: arsenal.NewSubfinderRunner(),
	}
}

type ReconResult struct {
	EngagementID string
	TargetID     string
	TargetSpec   arsenal.TargetSpec
	Subdomains   []string
	DurationSec  float64
}

func recordAuditLog(ctx context.Context, db *database.DB, engagementID, actor, action string, details map[string]interface{}) {
	if db == nil {
		return
	}
	payloadBytes, _ := json.Marshal(details)
	_, _ = db.ExecContext(ctx,
		`INSERT INTO audit_logs (engagement_id, actor, action, details) VALUES ($1, $2, $3, $4::jsonb)`,
		engagementID, actor, action, string(payloadBytes),
	)
}

func (r *ReconWorker) Execute(ctx context.Context, rawTarget string) (*ReconResult, error) {
	start := time.Now()
	spec := arsenal.NormalizeTarget(rawTarget)
	if spec.Domain == "" {
		return nil, fmt.Errorf("empty target")
	}

	log.Printf("[Agent:ReconWorker] Starting reconnaissance on %s (root=%s)...", spec.Raw, spec.RootURL)

	// 1. Register engagement & target in PostgreSQL
	var engagementID string
	code := fmt.Sprintf("ENG-%08X", time.Now().UnixNano()&0xFFFFFFFF)
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO engagements (code, target_url, authorized_scope, status)
		 VALUES ($1, $2, $3, 'ACTIVE')
		 ON CONFLICT (code) DO UPDATE SET status = 'ACTIVE'
		 RETURNING id`,
		code,
		spec.RootURL,
		spec.Raw,
	).Scan(&engagementID)
	if err != nil {
		return nil, fmt.Errorf("failed to register engagement: %w", err)
	}

	var targetID string
	err = r.db.QueryRowContext(ctx,
		`INSERT INTO targets (engagement_id, domain, root_url)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		engagementID, spec.Domain, spec.RootURL,
	).Scan(&targetID)
	if err != nil {
		_, _ = r.db.ExecContext(ctx, `UPDATE engagements SET status = 'FAILED', finished_at = CURRENT_TIMESTAMP WHERE id = $1`, engagementID)
		return nil, fmt.Errorf("failed to register target: %w", err)
	}

	// 2. Create recon task & log start audit
	var taskID string
	_ = r.db.QueryRowContext(ctx,
		`INSERT INTO tasks (engagement_id, agent_role, title, status, priority, input_context)
		 VALUES ($1, 'RECON', 'Host & Subdomain Enumeration', 'RUNNING', 9, $2::jsonb)
		 RETURNING id`,
		engagementID,
		fmt.Sprintf(`{"target": %q, "domain": %q}`, spec.Raw, spec.Domain),
	).Scan(&taskID)
	recordAuditLog(ctx, r.db, engagementID, "ReconWorker", "RECON_STARTED", map[string]interface{}{
		"target": spec.Raw,
		"domain": spec.Domain,
	})

	// 3. Run enumeration (external subfinder if available + native DNS/CT fallback)
	subs, err := r.subfinder.Enumerate(ctx, spec.Raw)
	if err != nil || len(subs) == 0 {
		hostVal := spec.HostWithPort
		if hostVal == "" {
			hostVal = spec.Domain
		}
		subs = []string{hostVal}
	}

	// 4. Persist discovered hosts into PostgreSQL asset_nodes
	tx, txErr := r.db.BeginTx(ctx, nil)
	if txErr == nil {
		stmt, prepErr := tx.PrepareContext(ctx,
			`INSERT INTO asset_nodes (target_id, kind, value, attributes)
			 VALUES ($1, 'SUBDOMAIN', $2, $3::jsonb)
			 ON CONFLICT (target_id, kind, value) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`,
		)
		if prepErr == nil {
			attrBytes, _ := json.Marshal(map[string]interface{}{
				"source":      "go_recon",
				"root_target": spec.Raw,
			})
			for _, sub := range subs {
				_, _ = stmt.ExecContext(ctx, targetID, sub, string(attrBytes))
			}
			_ = stmt.Close()
		}
		_ = tx.Commit()
	}

	duration := time.Since(start).Seconds()
	if taskID != "" {
		summaryBytes, _ := json.Marshal(map[string]interface{}{
			"hosts_discovered": len(subs),
			"duration_sec":     duration,
		})
		_, _ = r.db.ExecContext(ctx,
			"UPDATE tasks SET status = 'COMPLETED', output_summary = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
			taskID, string(summaryBytes),
		)
	}
	recordAuditLog(ctx, r.db, engagementID, "ReconWorker", "RECON_COMPLETED", map[string]interface{}{
		"target":           spec.Raw,
		"hosts_discovered": len(subs),
		"duration_sec":     duration,
	})

	log.Printf("[Agent:ReconWorker] Stored %d host assets in PostgreSQL in %.2fs", len(subs), duration)

	return &ReconResult{
		EngagementID: engagementID,
		TargetID:     targetID,
		TargetSpec:   spec,
		Subdomains:   subs,
		DurationSec:  duration,
	}, nil
}
