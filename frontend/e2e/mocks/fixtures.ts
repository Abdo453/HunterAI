import type { Page, Route } from "@playwright/test";

export interface MockApiOptions {
  localOnlyPolicy?: boolean;
  sseFailFirstAttempt?: boolean;
  slowCopilotStream?: boolean;
}

export const MOCK_RUN_ID = "run-e2e-001";
export const MOCK_ENGAGEMENT_ID = "eng-e2e-001";
export const MOCK_APPROVAL_ID = "appr-e2e-001";

export async function installPlatformMocks(page: Page, options: MockApiOptions = {}) {
  let sseAttempts = 0;
  let approvalStatus = "pending";
  let lastSeenEventId: string | null = null;
  let copilotConvCreated = false;

  const state = {
    get sseAttempts() {
      return sseAttempts;
    },
    get lastSeenEventId() {
      return lastSeenEventId;
    },
    get approvalStatus() {
      return approvalStatus;
    },
  };

  await page.route("**/api/**", async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const pathname = url.pathname;
    const method = req.method().toUpperCase();

    const json = (body: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(body),
      });

    if (pathname === "/api/csrf") {
      return route.fulfill({
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": "csrftoken=e2e-csrf-token-12345; Path=/; SameSite=Lax",
        },
        body: JSON.stringify({ csrfToken: "e2e-csrf-token-12345" }),
      });
    }

    if (pathname === "/api/platform/stream") {
      sseAttempts += 1;
      lastSeenEventId = req.headers()["last-event-id"] || url.searchParams.get("since_seq");
      if (options.sseFailFirstAttempt && sseAttempts === 1) {
        return route.abort("failed");
      }
      const eventsBody =
        sseAttempts > 1
          ? [
              "id: 11",
              "event: run_progress",
              `data: ${JSON.stringify({ seq: 11, type: "RUN_PROGRESS", message: "Recovered stream event #11 after reconnect", run_id: MOCK_RUN_ID })}`,
              "",
              "",
            ].join("\n")
          : [
              "id: 10",
              "event: heartbeat",
              `data: ${JSON.stringify({ seq: 10, type: "HEARTBEAT", message: "SSE live stream active", run_id: MOCK_RUN_ID })}`,
              "",
              "",
            ].join("\n");

      return route.fulfill({
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
        },
        body: eventsBody,
      });
    }

    if (pathname === "/api/platform/overview") {
      return json({
        status: "ok",
        latest_seq: 10,
        context: {
          active_engagement_id: MOCK_ENGAGEMENT_ID,
          active_run_id: MOCK_RUN_ID,
        },
        engagements: [
          {
            engagement_id: MOCK_ENGAGEMENT_ID,
            name: "Juice Shop E2E",
            target: "target.local",
            in_scope: ["target.local"],
            out_of_scope: [],
            status: "active",
          },
        ],
        runs: [
          {
            run_id: MOCK_RUN_ID,
            kind: "omni",
            target: "target.local",
            engagement_id: MOCK_ENGAGEMENT_ID,
            status: "paused",
            current_phase: "verification",
            progress: 0.45,
            checkpoint_id: "chk-e2e-01",
            recoverable: true,
          },
        ],
        assets: [
          {
            id: "asset-1",
            kind: "endpoint",
            value: "https://target.local/api/orders/1002",
            attributes: { status: 200, title: "Orders API" },
          },
        ],
        findings: [
          {
            id: "finding-1",
            title: "IDOR in Orders API",
            vuln_class: "idor",
            severity: "high",
            cvss_score: 8.1,
            confidence: 0.94,
            endpoint: "https://target.local/api/orders/1002",
            evidence: "Cross-tenant order body returned HTTP 200",
            status: "confirmed",
          },
        ],
        pending_approvals: [
          {
            approval_id: MOCK_APPROVAL_ID,
            run_id: MOCK_RUN_ID,
            action_type: "tool_exec",
            target: "target.local",
            tool_name: "nuclei",
            command_args: "nuclei -u https://target.local -severity high",
            risk_tier: "HIGH",
            rationale: "Confirm IDOR exposure",
            status: approvalStatus,
            proposal_digest: "sha256:abcdef1234567890",
            created_at: 1732650000,
          },
        ],
        unread_notifications: [
          {
            notification_id: "notif-1",
            level: "warning",
            title: "Approval Needed",
            message: "Nuclei verification awaiting decision",
            read: false,
            created_at: 1732650000,
          },
        ],
        counts: {
          engagements: 1,
          runs: 1,
          active_runs: 1,
          pending_approvals: approvalStatus === "pending" ? 1 : 0,
          findings: 1,
          assets: 1,
          leads: 1,
          conversations: 1,
          unread_notifications: 1,
          tools_installed: 12,
          agents: 6,
        },
        services: {
          ollama: { online: true, host: "http://127.0.0.1:11434" },
          cloud_providers: ["nvidia"],
        },
      });
    }

    if (pathname === "/api/platform/notifications") {
      return json({
        notifications: [
          {
            notification_id: "notif-1",
            level: "warning",
            title: "Approval Needed",
            message: "Nuclei verification awaiting decision",
            read: false,
            created_at: 1732650000,
          },
        ],
      });
    }

    if (pathname.startsWith("/api/platform/notifications/") && pathname.endsWith("/read")) {
      return json({ ok: true });
    }

    if (pathname === "/api/artex/health") {
      return json({ online: true, status: "ok", health: { status: "ok", database: "connected" } });
    }

    if (pathname === "/api/artex/stats") {
      return json({ online: true, data: { total_assets: 1, total_findings: 1, total_engagements: 1, status: "ONLINE" } });
    }

    if (pathname === "/api/artex/tasks") {
      return json({
        online: true,
        data: [
          {
            id: "task-e2e-1",
            run_id: MOCK_RUN_ID,
            agent_role: "recon-agent",
            title: "Enumerate API routes",
            status: "completed",
            priority: 1,
            input_context: {},
            output_summary: { endpoints: 14 },
            subtasks: [
              {
                subtask_id: "sub-1",
                task_id: "task-e2e-1",
                title: "Probe /api/orders endpoint",
                status: "completed",
              },
            ],
          },
        ],
      });
    }

    if (pathname === "/api/artex/audit-logs") {
      return json({ online: true, data: [] });
    }

    if (pathname === "/api/system/hardware") {
      return json({
        cpu: { status: "ok", percent: 28.4, logical_cores: 16, physical_cores: 8 },
        ram: { status: "ok", total_mb: 32768, used_mb: 14336, available_mb: 18432, percent: 43.8 },
        gpu: {
          status: "available",
          available: true,
          source: "nvidia-smi",
          count: 1,
          gpus: [
            {
              index: 0,
              name: "NVIDIA RTX 4060 Laptop GPU",
              vram_total_mb: 8192,
              vram_used_mb: 3072,
              vram_free_mb: 5120,
              vram_used_pct: 37.5,
              utilization_pct: 22,
            },
          ],
          vram_total_mb: 8192,
          vram_used_mb: 3072,
          vram_free_mb: 5120,
          vram_used_pct: 37.5,
        },
        ollama: {
          status: "online",
          host: "http://127.0.0.1:11434",
          loaded_models: [{ name: "qwen2.5:14b", size_mb: 8400, size_vram_mb: 3072 }],
        },
        hardware_profile: {
          active: "rtx4060-8gb",
          default_num_ctx: 8192,
          keep_alive_seconds: 300,
        },
      });
    }

    if (pathname === "/api/budget") {
      return json({
        global_usd: 1.42,
        today_usd: 0.38,
        global_tokens: 184200,
        calls: 27,
        budget: { per_run_usd: 5, per_solver_usd: 1.5, per_day_usd: 20 },
        by_provider: {
          ollama: { usd: 0, tokens: 120000, calls: 18 },
          nvidia: { usd: 1.42, tokens: 64200, calls: 9 },
        },
        by_model: {
          "qwen2.5:14b": { usd: 0, tokens: 120000, calls: 18 },
          "deepseek-r1": { usd: 1.42, tokens: 64200, calls: 9 },
        },
      });
    }

    if (pathname === "/api/models/catalog") {
      return json({
        policy: options.localOnlyPolicy ? "local_only" : "balanced",
        choices: [
          {
            id: "local:qwen2.5:14b",
            label: "Ollama · qwen2.5:14b",
            kind: "local",
            provider: "ollama",
            model: "qwen2.5:14b",
            available: true,
            supports_tools: true,
          },
          {
            id: "api:nvidia:deepseek-r1",
            label: "Nvidia NIM · deepseek-r1",
            kind: "cloud",
            provider: "nvidia",
            model: "deepseek-r1",
            available: true,
            supports_tools: true,
            supports_thinking: true,
          },
        ],
      });
    }

    if (pathname === "/api/copilot/conversations") {
      if (method === "POST") {
        copilotConvCreated = true;
        return json({
          conversation: {
            conversation_id: "conv-e2e-2",
            title: "Second Thread",
            mode: "analyst",
            model: "auto",
          },
        });
      }
      const list = [
        { conversation_id: "conv-e2e-1", title: "Primary Investigation", mode: "analyst", model: "auto" },
      ];
      if (copilotConvCreated) {
        list.unshift({ conversation_id: "conv-e2e-2", title: "Second Thread", mode: "analyst", model: "auto" });
      }
      return json({ conversations: list });
    }

    if (pathname.startsWith("/api/copilot/conversations/")) {
      return json({
        conversation: { conversation_id: "conv-e2e-1", title: "Primary Investigation", mode: "analyst", model: "auto" },
        messages: [],
      });
    }

    if (pathname === "/api/copilot/chat/stream") {
      if (options.slowCopilotStream) {
        await new Promise((resolve) => setTimeout(resolve, 600));
      }
      const sse = [
        "event: start",
        `data: ${JSON.stringify({ conversation_id: "conv-e2e-1", model: "local:qwen2.5:14b" })}`,
        "",
        "event: thinking",
        `data: ${JSON.stringify({ delta: "Inspecting scoped endpoint /api/orders/1002..." })}`,
        "",
        "event: citations",
        `data: ${JSON.stringify({ citations: [{ kind: "finding", id: "finding-1", label: "IDOR in Orders API" }] })}`,
        "",
        "event: approval_request",
        `data: ${JSON.stringify({
          approval: {
            approval_id: MOCK_APPROVAL_ID,
            action_type: "tool_exec",
            tool_name: "nuclei",
            target: "target.local",
            command_args: "nuclei -u https://target.local -severity high",
            risk_tier: "HIGH",
            proposal_digest: "sha256:abcdef1234567890",
            status: approvalStatus,
          },
        })}`,
        "",
        "event: token",
        `data: ${JSON.stringify({ delta: "Verified cross-tenant IDOR signal on target.local." })}`,
        "",
        "event: done",
        `data: ${JSON.stringify({
          conversation_id: "conv-e2e-1",
          answer: "Verified cross-tenant IDOR signal on target.local.",
          model_used: "local:qwen2.5:14b",
          refs: [{ kind: "file", id: "scripts/probe.py", label: "scripts/probe.py" }],
        })}`,
        "",
        "",
      ].join("\n");
      return route.fulfill({
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
        body: sse,
      });
    }

    if (pathname.startsWith("/api/approvals/") && pathname.endsWith("/decide")) {
      approvalStatus = "approved";
      return json({
        ok: true,
        approval: {
          approval_id: MOCK_APPROVAL_ID,
          status: "approved",
          decided_by: "operator",
        },
        execution: {
          executed: true,
          blocked: false,
          returncode: 0,
          stdout_excerpt: "[INF] nuclei scan completed cleanly: 1 high finding confirmed",
          stderr_excerpt: "",
        },
      });
    }

    if (pathname.startsWith("/api/platform/runs/") && pathname.endsWith("/recover")) {
      return json({
        ok: true,
        run: { run_id: MOCK_RUN_ID, kind: "omni", target: "target.local", status: "running", progress: 0.5 },
      });
    }

    if (pathname === "/api/evidence/ledger") {
      return json({
        counts: { court_verdict: 1, evidence: 1 },
        recent: {
          court_verdict: [
            {
              court_id: "court-1",
              finding_id: "finding-1",
              title: "IDOR in Orders API",
              endpoint: "https://target.local/api/orders/1002",
              verdict: "CONFIRMED",
              reason_code: "E3_REPRODUCED",
              rationale: "Differential auth check confirmed unauthorized invoice read.",
            },
          ],
          evidence: [],
        },
      });
    }

    if (pathname === "/api/vuln-intel/search") {
      return json({
        ok: true,
        status: "ok",
        source: "local",
        total_in_db: 120,
        count: 1,
        results: [
          {
            id: "CVE-2025-1001",
            title: "Sample Auth Bypass Advisory",
            severity: "HIGH",
            cvss_score: 8.6,
            ecosystem: "npm",
            summary: "Example local advisory record.",
          },
        ],
      });
    }

    if (pathname === "/api/vuln-intel/coverage") {
      return json({ ok: true, stored_count: 120, completeness: "partial" });
    }

    if (pathname === "/api/vuln-intel/sync") {
      return json({ ok: true, stored_count: 120, schema_version: 2 });
    }

    // Default safe JSON response for secondary page polls
    return json({ ok: true, items: [], results: [], categories: [], tools: [], skills: [], agents: [], models: [], servers: [] });
  });

  return state;
}

export async function applyMatrixMode(page: Page, theme: "dark" | "light", lang: "en" | "ar") {
  await page.addInitScript(
    ({ th, lg }) => {
      window.localStorage.setItem("hunterai_theme", th);
      window.localStorage.setItem("theme", th);
      window.localStorage.setItem("hunterai_lang", lg);
      window.localStorage.setItem("lang", lg);
    },
    { th: theme, lg: lang }
  );
}
