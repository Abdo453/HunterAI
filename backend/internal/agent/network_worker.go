package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
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
	EndpointsList []string
	DurationSec   float64
}

func (n *NetworkWorker) Execute(ctx context.Context, engagementID, targetID string, rawTarget string, sampleLimit int) (*NetworkResult, error) {
	start := time.Now()
	log.Printf("[Agent:NetworkWorker] Fetching host assets for target %s (limit: %d)...", targetID, sampleLimit)

	rows, err := n.db.QueryContext(ctx,
		`SELECT value FROM asset_nodes
		 WHERE target_id = $1 AND kind = 'SUBDOMAIN'
		 ORDER BY first_seen ASC LIMIT $2`,
		targetID, sampleLimit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch asset nodes: %w", err)
	}
	defer rows.Close()

	var hosts []string
	seenHost := make(map[string]bool)
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err == nil && host != "" && !seenHost[host] {
			seenHost[host] = true
			hosts = append(hosts, host)
		}
	}

	// Ensure explicit user URL with path/scheme (if any) is also probed first
	var probeInputs []string
	if rawTarget != "" {
		probeInputs = append(probeInputs, rawTarget)
	}
	for _, h := range hosts {
		if h != rawTarget {
			probeInputs = append(probeInputs, h)
		}
	}
	if len(probeInputs) == 0 {
		return &NetworkResult{LiveEndpoints: 0, DurationSec: 0}, nil
	}

	var taskID string
	_ = n.db.QueryRowContext(ctx,
		`INSERT INTO tasks (engagement_id, agent_role, title, status, priority, input_context)
		 VALUES ($1, 'NETWORK', 'Live HTTP/HTTPS Probing & Fingerprinting', 'RUNNING', 8, $2::jsonb)
		 RETURNING id`,
		engagementID,
		fmt.Sprintf(`{"hosts_count": %d}`, len(probeInputs)),
	).Scan(&taskID)

	probes, err := n.httpx.Probe(ctx, probeInputs)
	if err != nil {
		if taskID != "" {
			_, _ = n.db.ExecContext(ctx,
				`UPDATE tasks SET status = 'FAILED', output_summary = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
				taskID, fmt.Sprintf(`{"error": %q}`, err.Error()),
			)
		}
		recordAuditLog(ctx, n.db, engagementID, "NetworkWorker", "NETWORK_PROBE_FAILED", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, err
	}

	var discoveredEndpoints []string
	tx, err := n.db.BeginTx(ctx, nil)
	if err == nil {
		updStmt, _ := tx.PrepareContext(ctx,
			`UPDATE asset_nodes
			 SET attributes = attributes || $1::jsonb, updated_at = CURRENT_TIMESTAMP
			 WHERE target_id = $2 AND kind = 'SUBDOMAIN' AND value = $3`,
		)
		epStmt, _ := tx.PrepareContext(ctx,
			`INSERT INTO asset_nodes (target_id, kind, value, attributes)
			 VALUES ($1, 'ENDPOINT', $2, $3::jsonb)
			 ON CONFLICT (target_id, kind, value) DO UPDATE
			 SET attributes = asset_nodes.attributes || EXCLUDED.attributes, updated_at = CURRENT_TIMESTAMP`,
		)

		seenEP := make(map[string]bool)
		for _, probe := range probes {
			attr, _ := json.Marshal(map[string]interface{}{
				"live_url":         probe.URL,
				"status_code":      probe.StatusCode,
				"title":            probe.Title,
				"tech":             probe.Tech,
				"webserver":        probe.WebServer,
				"security_headers": probe.SecurityHeaders,
				"tls_issuer":       probe.TLSIssuer,
				"tls_valid":        probe.TLSValid,
			})
			if updStmt != nil {
				_, _ = updStmt.ExecContext(ctx, string(attr), targetID, probe.Input)
				// Also match normalized host:port or host when Input was a full URL
				if spec := arsenal.NormalizeTarget(probe.Input); spec.HostWithPort != "" && spec.HostWithPort != probe.Input {
					_, _ = updStmt.ExecContext(ctx, string(attr), targetID, spec.HostWithPort)
				}
			}

			if !seenEP[probe.URL] {
				seenEP[probe.URL] = true
				discoveredEndpoints = append(discoveredEndpoints, probe.URL)
				if epStmt != nil {
					_, _ = epStmt.ExecContext(ctx, targetID, probe.URL, string(attr))
				}
			}
			for _, ep := range probe.Endpoints {
				if seenEP[ep] || len(seenEP) >= 25 {
					continue
				}
				seenEP[ep] = true
				discoveredEndpoints = append(discoveredEndpoints, ep)
				if epStmt != nil {
					kindLabel := "ENDPOINT"
					if u, pErr := url.Parse(ep); pErr == nil && len(u.Path) > 0 {
						if u.RawQuery != "" || len(u.Path) >= 4 && (u.Path[:4] == "/api" || u.Path[:3] == "/v1" || u.Path[:3] == "/v2") {
							_ = kindLabel
						}
					}
					epAttr, _ := json.Marshal(map[string]interface{}{
						"source": "html_crawl",
						"parent": probe.URL,
						"url":    ep,
					})
					_, _ = epStmt.ExecContext(ctx, targetID, ep, string(epAttr))
				}
			}
		}

		if updStmt != nil {
			_ = updStmt.Close()
		}
		if epStmt != nil {
			_ = epStmt.Close()
		}
		_ = tx.Commit()
	}

	duration := time.Since(start).Seconds()
	if taskID != "" {
		summaryBytes, _ := json.Marshal(map[string]interface{}{
			"live_hosts":          len(probes),
			"endpoints_collected": len(discoveredEndpoints),
			"duration_sec":        duration,
		})
		_, _ = n.db.ExecContext(ctx,
			"UPDATE tasks SET status = 'COMPLETED', output_summary = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
			taskID, string(summaryBytes),
		)
	}
	recordAuditLog(ctx, n.db, engagementID, "NetworkWorker", "NETWORK_PROBE_COMPLETED", map[string]interface{}{
		"live_hosts":          len(probes),
		"endpoints_collected": len(discoveredEndpoints),
		"duration_sec":        duration,
	})

	log.Printf("[Agent:NetworkWorker] Network probe completed: %d live roots, %d endpoints in %.2fs", len(probes), len(discoveredEndpoints), duration)

	return &NetworkResult{
		LiveEndpoints: len(probes),
		EndpointsList: discoveredEndpoints,
		DurationSec:   duration,
	}, nil
}
