package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"artex-pro/internal/arsenal"
	"artex-pro/internal/database"
)

type VulnWorker struct {
	db     *database.DB
	nuclei *arsenal.NucleiRunner
}

func NewVulnWorker(db *database.DB) *VulnWorker {
	return &VulnWorker{
		db:     db,
		nuclei: arsenal.NewNucleiRunner(),
	}
}

type VulnResult struct {
	FindingsCount int
	DurationSec   float64
}

func (v *VulnWorker) Execute(ctx context.Context, engagementID, targetID string, endpoints []string) (*VulnResult, error) {
	start := time.Now()
	if len(endpoints) == 0 {
		return &VulnResult{FindingsCount: 0, DurationSec: 0}, nil
	}

	log.Printf("[Agent:VulnWorker] Initiating vulnerability testing on %d target endpoints...", len(endpoints))

	findings, err := v.nuclei.Scan(ctx, endpoints, []string{"low", "medium", "high", "critical"})
	if err != nil {
		return nil, fmt.Errorf("vuln scan failed: %w", err)
	}

	// Insert findings into PostgreSQL findings table
	tx, err := v.db.BeginTx(ctx, nil)
	if err == nil {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO findings (engagement_id, target_id, title, vuln_class, severity, confidence, cvss_score, endpoint, evidence, poc_details, status)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, 'TRIAGED')`,
		)
		if err == nil {
			engParam := sql.NullString{String: engagementID, Valid: engagementID != ""}
			targetParam := sql.NullString{String: targetID, Valid: targetID != ""}
			for _, f := range findings {
				pocMap := map[string]interface{}{
					"template_id":  f.TemplateID,
					"curl_command": f.CurlCommand,
					"description":  f.Info.Description,
					"tags":         f.Info.Tags,
				}
				pocBytes, _ := json.Marshal(pocMap)

				sev := f.Info.Severity
				cvss := 5.0
				switch sev {
				case "critical":
					cvss = 9.8
				case "high":
					cvss = 8.0
				case "medium":
					cvss = 5.5
				case "low":
					cvss = 3.0
				}

				evidence := f.CurlCommand
				if evidence == "" {
					evidence = f.MatchedAt
				}

				_, _ = stmt.ExecContext(ctx,
					engParam,
					targetParam,
					f.Info.Name,
					f.TemplateID,
					sev,
					0.90,
					cvss,
					f.MatchedAt,
					evidence,
					string(pocBytes),
				)
			}
			_ = stmt.Close()
		}
		_ = tx.Commit()
	}

	duration := time.Since(start).Seconds()
	log.Printf("[Agent:VulnWorker] Vulnerability phase completed: %d findings recorded in %.2fs", len(findings), duration)

	return &VulnResult{
		FindingsCount: len(findings),
		DurationSec:   duration,
	}, nil
}
