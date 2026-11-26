package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"artex-pro/internal/database"
)

type Orchestrator struct {
	db      *database.DB
	recon   *ReconWorker
	network *NetworkWorker
	vuln    *VulnWorker
}

func NewOrchestrator(db *database.DB) *Orchestrator {
	return &Orchestrator{
		db:      db,
		recon:   NewReconWorker(db),
		network: NewNetworkWorker(db),
		vuln:    NewVulnWorker(db),
	}
}

type MissionSummary struct {
	TargetDomain   string  `json:"target_domain"`
	EngagementID   string  `json:"engagement_id"`
	TotalAssets    int     `json:"total_assets"`
	LiveEndpoints  int     `json:"live_endpoints"`
	TotalFindings  int     `json:"total_findings"`
	DurationSec    float64 `json:"duration_sec"`
	EngagementCode string  `json:"engagement_code"`
}

func (o *Orchestrator) RunAutonomousMission(ctx context.Context, rawTarget string) (*MissionSummary, error) {
	start := time.Now()
	log.Printf("[Orchestrator] Launching ARTEX-Pro Autonomous Pipeline for: %s", rawTarget)

	// Step 1: Reconnaissance
	reconRes, err := o.recon.Execute(ctx, rawTarget)
	if err != nil || reconRes == nil {
		return nil, fmt.Errorf("recon stage failed: %v", err)
	}

	// Step 2: Network / Live HTTP Probing
	liveEndpointsCount := 0
	netRes, err := o.network.Execute(ctx, reconRes.EngagementID, reconRes.TargetID, reconRes.TargetSpec.Raw, 50)
	if err != nil {
		log.Printf("[Orchestrator] Network probe warning: %v", err)
	} else if netRes != nil {
		liveEndpointsCount = netRes.LiveEndpoints
	}

	// Step 3: Collect live URLs for security scanning
	rows, err := o.db.QueryContext(ctx,
		`SELECT attributes->>'live_url'
		 FROM asset_nodes
		 WHERE target_id = $1 AND attributes ? 'live_url'
		 LIMIT 25`,
		reconRes.TargetID,
	)
	var liveURLs []string
	seenURL := make(map[string]bool)
	if err == nil {
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err == nil && u != "" && !seenURL[u] {
				seenURL[u] = true
				liveURLs = append(liveURLs, u)
			}
		}
		rows.Close()
	}

	// Step 4: Security Checks & Vulnerability Audit
	var totalFindings int
	if len(liveURLs) > 0 {
		vulnRes, vErr := o.vuln.Execute(ctx, reconRes.EngagementID, reconRes.TargetID, liveURLs)
		if vErr == nil && vulnRes != nil {
			totalFindings = vulnRes.FindingsCount
		} else if vErr != nil {
			log.Printf("[Orchestrator] Vuln scan warning: %v", vErr)
		}
	} else {
		recordAuditLog(ctx, o.db, reconRes.EngagementID, "Orchestrator", "NO_LIVE_HTTP_ENDPOINTS", map[string]interface{}{
			"target": rawTarget,
			"note":   "Host did not answer HTTP/HTTPS probes within timeout",
		})
	}

	duration := time.Since(start).Seconds()

	var totalAssets int
	_ = o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_nodes WHERE target_id = $1`, reconRes.TargetID).Scan(&totalAssets)

	_, _ = o.db.ExecContext(ctx,
		`UPDATE engagements SET status = 'COMPLETED', finished_at = CURRENT_TIMESTAMP WHERE id = $1`,
		reconRes.EngagementID,
	)
	recordAuditLog(ctx, o.db, reconRes.EngagementID, "Orchestrator", "MISSION_COMPLETED", map[string]interface{}{
		"target":         rawTarget,
		"total_assets":   totalAssets,
		"live_endpoints": liveEndpointsCount,
		"findings":       totalFindings,
		"duration_sec":   duration,
	})

	summary := &MissionSummary{
		TargetDomain:  reconRes.TargetSpec.Domain,
		EngagementID:  reconRes.EngagementID,
		TotalAssets:   totalAssets,
		LiveEndpoints: liveEndpointsCount,
		TotalFindings: totalFindings,
		DurationSec:   duration,
	}

	log.Printf("[Orchestrator] Pipeline completed for %s: %d assets, %d live, %d findings in %.2fs",
		summary.TargetDomain, summary.TotalAssets, summary.LiveEndpoints, summary.TotalFindings, summary.DurationSec)

	return summary, nil
}
