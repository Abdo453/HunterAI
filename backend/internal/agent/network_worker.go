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

type NetworkWorker struct {
	db    *database.DB
	httpx *arsenal.HTTPXRunner
}

func NewNetworkWorker(db *database.DB) *NetworkWorker {
	return &NetworkWorker{
		db:    db,
		httpx: arsenal.NewHTTPXRunner(),
	}
}

type NetworkResult struct {
	LiveEndpoints int
	DurationSec   float64
}

func (n *NetworkWorker) Execute(ctx context.Context, targetID string, sampleLimit int) (*NetworkResult, error) {
	start := time.Now()
	log.Printf("[Agent:NetworkWorker] Fetching asset subdomains for target %s (limit: %d)...", targetID, sampleLimit)

	rows, err := n.db.QueryContext(ctx,
		`SELECT value FROM asset_nodes 
		 WHERE target_id = $1 AND kind = 'SUBDOMAIN' 
		 ORDER BY id ASC LIMIT $2`,
		targetID, sampleLimit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch asset nodes: %w", err)
	}
	defer rows.Close()

	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err == nil {
			hosts = append(hosts, host)
		}
	}

	if len(hosts) == 0 {
		return &NetworkResult{LiveEndpoints: 0, DurationSec: 0}, nil
	}

	log.Printf("[Agent:NetworkWorker] Probing %d hosts with HTTPX...", len(hosts))
	probes, err := n.httpx.Probe(ctx, hosts)
	if err != nil {
		return nil, err
	}

	// Update asset_nodes with HTTP metadata
	tx, err := n.db.BeginTx(ctx, nil)
	if err == nil {
		stmt, err := tx.PrepareContext(ctx,
			`UPDATE asset_nodes 
			 SET attributes = attributes || $1::jsonb, updated_at = CURRENT_TIMESTAMP
			 WHERE target_id = $2 AND kind = 'SUBDOMAIN' AND value = $3`,
		)
		if err == nil {
			for _, probe := range probes {
				attr, _ := json.Marshal(map[string]interface{}{
					"live_url":    probe.URL,
					"status_code": probe.StatusCode,
					"title":       probe.Title,
					"tech":        probe.Tech,
					"webserver":   probe.WebServer,
				})
				_, _ = stmt.ExecContext(ctx, string(attr), targetID, probe.Input)
			}
			_ = stmt.Close()
		}
		_ = tx.Commit()
	}

	duration := time.Since(start).Seconds()
	log.Printf("[Agent:NetworkWorker] Network probe phase completed: %d live endpoints identified in %.2fs", len(probes), duration)

	return &NetworkResult{
		LiveEndpoints: len(probes),
		DurationSec:   duration,
	}, nil
}
