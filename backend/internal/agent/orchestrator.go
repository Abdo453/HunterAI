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
	TotalAssets    int     `json:"total_assets"`
	LiveEndpoints  int     `json:"live_endpoints"`
	TotalFindings  int     `json:"total_findings"`
	DurationSec    float64 `json:"duration_sec"`
	EngagementCode string  `json:"engagement_code"`
}

func (o *Orchestrator) RunAutonomousMission(ctx context.Context, targetDomain string) (*MissionSummary, error) {
	start := time.Now()
	log.Printf("[Orchestrator] 🚀 Launching ARTEX-Pro Autonomous Pipeline for: %s", targetDomain)

	// Step 1: Reconnaissance
	reconRes, err := o.recon.Execute(ctx, targetDomain)
	if err != nil {
		return nil, fmt.Errorf("recon stage failed: %w", err)
	}

	// Step 2: Network / Live Host Probing
	netRes, err := o.network.Execute(ctx, reconRes.TargetID, 50)
	if err != nil {
		log.Printf("[Orchestrator] Network probe warning: %v", err)
	}

	// Step 3: Get live URLs for vulnerability scanning
	rows, err := o.db.QueryContext(ctx,
		`SELECT attributes->>'live_url' 
		 FROM asset_nodes 
		 WHERE target_id = $1 AND attributes ? 'live_url'
		 LIMIT 20`,
		reconRes.TargetID,
	)
	var liveURLs []string
	if err == nil {
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err == nil && u != "" {
				liveURLs = append(liveURLs, u)
			}
		}
		rows.Close()
	}

	// Step 4: Vulnerability Scanning
	var totalFindings int
	if len(liveURLs) > 0 {
		var engID string
		_ = o.db.QueryRowContext(ctx, `SELECT engagement_id FROM targets WHERE id = $1`, reconRes.TargetID).Scan(&engID)
		vulnRes, err := o.vuln.Execute(ctx, engID, reconRes.TargetID, liveURLs)
		if err == nil {
			totalFindings = vulnRes.FindingsCount
		} else {
			log.Printf("[Orchestrator] Vuln scan note: %v", err)
		}
	}

	duration := time.Since(start).Seconds()

	var totalAssets int
	_ = o.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_nodes WHERE target_id = $1`, reconRes.TargetID).Scan(&totalAssets)

	summary := &MissionSummary{
		TargetDomain:  targetDomain,
		TotalAssets:   totalAssets,
		LiveEndpoints: netRes.LiveEndpoints,
		TotalFindings: totalFindings,
		DurationSec:   duration,
	}

	log.Printf("[Orchestrator] 🏁 Pipeline completed for %s: %d assets, %d live, %d findings in %.2fs",
		targetDomain, summary.TotalAssets, summary.LiveEndpoints, summary.TotalFindings, summary.DurationSec)

	return summary, nil
}
