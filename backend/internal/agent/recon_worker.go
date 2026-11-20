package agent

import (
	"context"
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
	TargetID    string
	Subdomains  []string
	DurationSec float64
}

func (r *ReconWorker) Execute(ctx context.Context, targetDomain string) (*ReconResult, error) {
	start := time.Now()
	log.Printf("[Agent:ReconWorker] Starting autonomous reconnaissance on %s...", targetDomain)

	// 1. Create or get engagement & target in DB
	var engagementID string
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO engagements (code, target_url, authorized_scope, status)
		 VALUES ($1, $2, $3, 'ACTIVE')
		 ON CONFLICT (code) DO UPDATE SET status = 'ACTIVE'
		 RETURNING id`,
		"ENG-"+fmt.Sprintf("%X", time.Now().Unix())[:8],
		"https://"+targetDomain,
		targetDomain,
	).Scan(&engagementID)
	if err != nil {
		return nil, fmt.Errorf("failed to register engagement: %w", err)
	}

	var targetID string
	err = r.db.QueryRowContext(ctx,
		`INSERT INTO targets (engagement_id, domain, root_url)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		engagementID, targetDomain, "https://"+targetDomain,
	).Scan(&targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to register target: %w", err)
	}

	// 2. Log task
	var taskID string
	_ = r.db.QueryRowContext(ctx,
		`INSERT INTO tasks (engagement_id, agent_role, title, status, priority)
		 VALUES ($1, 'RECON', 'Passive Subdomain Enumeration', 'RUNNING', 9)
		 RETURNING id`,
		engagementID,
	).Scan(&taskID)

	// 3. Run Subfinder enumeration
	subs, err := r.subfinder.Enumerate(ctx, targetDomain)
	if err != nil {
		if taskID != "" {
			_, _ = r.db.ExecContext(ctx, "UPDATE tasks SET status = 'FAILED' WHERE id = $1", taskID)
		}
		return nil, err
	}

	// 4. Batch insert discovered subdomains into PostgreSQL asset_nodes
	tx, err := r.db.BeginTx(ctx, nil)
	if err == nil {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO asset_nodes (target_id, kind, value, attributes)
			 VALUES ($1, 'SUBDOMAIN', $2, '{"source": "subfinder"}'::jsonb)
			 ON CONFLICT (target_id, kind, value) DO NOTHING`,
		)
		if err == nil {
			for _, sub := range subs {
				_, _ = stmt.ExecContext(ctx, targetID, sub)
			}
			_ = stmt.Close()
		}
		_ = tx.Commit()
	}

	// 5. Update task to completed
	if taskID != "" {
		_, _ = r.db.ExecContext(ctx,
			"UPDATE tasks SET status = 'COMPLETED', updated_at = CURRENT_TIMESTAMP WHERE id = $1",
			taskID,
		)
	}

	duration := time.Since(start).Seconds()
	log.Printf("[Agent:ReconWorker] Successfully stored %d assets in PostgreSQL in %.2fs", len(subs), duration)

	return &ReconResult{
		TargetID:    targetID,
		Subdomains:  subs,
		DurationSec: duration,
	}, nil
}
