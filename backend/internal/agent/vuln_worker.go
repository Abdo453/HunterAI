package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
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

	log.Printf("[Agent:VulnWorker] Initiating security audit on %d live endpoints...", len(endpoints))

	var taskID string
	_ = v.db.QueryRowContext(ctx,
		`INSERT INTO tasks (engagement_id, agent_role, title, status, priority, input_context)
		 VALUES ($1, 'WEB', 'Active Vulnerability & Security Misconfiguration Audit', 'RUNNING', 7, $2::jsonb)
		 RETURNING id`,
		engagementID,
		fmt.Sprintf(`{"endpoints_count": %d}`, len(endpoints)),
	).Scan(&taskID)

	findings, err := v.nuclei.Scan(ctx, endpoints, []string{"low", "medium", "high", "critical"})
	if err != nil {
		if taskID != "" {
			_, _ = v.db.ExecContext(ctx,
				`UPDATE tasks SET status = 'FAILED', output_summary = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
				taskID, fmt.Sprintf(`{"error": %q}`, err.Error()),
			)
		}
		return nil, fmt.Errorf("vuln scan failed: %w", err)
	}

	tx, err := v.db.BeginTx(ctx, nil)
	if err == nil {
		stmt, prepErr := tx.PrepareContext(ctx,
			`INSERT INTO findings (engagement_id, target_id, title, vuln_class, severity, confidence, cvss_score, endpoint, evidence, poc_details, status)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, 'TRIAGED')`,
		)
		if prepErr == nil {
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

				sev := strings.ToLower(strings.TrimSpace(f.Info.Severity))
				if sev == "" {
					sev = "info"
				}
				cvss := 0.0
				switch sev {
				case "critical":
					cvss = 9.8
				case "high":
					cvss = 8.0
				case "medium":
					cvss = 5.5
				case "low":
					cvss = 3.1
				case "info":
					cvss = 0.0
				}

				evidence := strings.TrimSpace(f.Info.Description)
				if f.CurlCommand != "" {
					if evidence != "" {
						evidence += "\n\nReproduce:\n" + f.CurlCommand
					} else {
						evidence = f.CurlCommand
					}
				}
				if evidence == "" {
					evidence = f.MatchedAt
				}

				_, _ = stmt.ExecContext(ctx,
					engParam,
					targetParam,
					f.Info.Name,
					f.TemplateID,
					strings.ToUpper(sev),
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
	if taskID != "" {
		summaryBytes, _ := json.Marshal(map[string]interface{}{
			"findings_count": len(findings),
			"duration_sec":   duration,
		})
		_, _ = v.db.ExecContext(ctx,
			"UPDATE tasks SET status = 'COMPLETED', output_summary = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
			taskID, string(summaryBytes),
		)
	}
	recordAuditLog(ctx, v.db, engagementID, "VulnWorker", "VULN_SCAN_COMPLETED", map[string]interface{}{
		"findings_count": len(findings),
		"endpoints":      len(endpoints),
		"duration_sec":   duration,
	})

	log.Printf("[Agent:VulnWorker] Vulnerability phase completed: %d findings recorded in %.2fs", len(findings), duration)

	return &VulnResult{
		FindingsCount: len(findings),
		DurationSec:   duration,
	}, nil
}
