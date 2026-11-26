# ARTEX-Pro Unified Next.js 15 Dashboard

Single unified web dashboard for the **ARTEX-Pro & HunterAI Autonomous Multi-Agent Security Platform**.

## Architecture
- **Framework**: Next.js 15 (App Router) + React 19 + TypeScript
- **Styling & i18n**: Obsidian Sentinel Dark / Paper Slate Light + Arabic (`RTL`) & English (`LTR`)
- **API & Streaming**:
  - REST `/api/*` rewritten to Django ASGI Hub (`HUNTER_API_BASE`, default `http://127.0.0.1:8000`)
  - Go Core telemetry & scans bridged through Django `/api/platform/artex/*` (no direct browser calls to `:7071`)
  - SSE (`/api/copilot/chat/stream`, `/api/platform/stream`) and WebSockets (`/ws/*`) connected directly to Django ASGI Hub with `credentials: "include"` + `X-CSRFToken`
- **Self-Hosted IDE Assets**: Local Monaco Editor served from `/vendor/monaco/vs`

## Routes
- `/` — Command Overview, Unified Mission Launcher, Managed Runs, Approvals Gate, Budget Guard, Live Console
- `/surface` — Attack Surface Topology Graph (`@xyflow/react`), Table View, Swarm Roster, Wiretap, Two-Brain Diff
- `/findings` — Triaged Findings, DOMPurify PoC Dossier, H1/HTML/MD/JSON Exports, Evidence Ledger, Snapshots
- `/operations` — Targets & Scope CRUD, Scope Validator, Red Team HMAC Grant, Checklists, 7-Question Gate, Lead Board
- `/studio` — Multi-Tab Self-Hosted Monaco Editor, Workspace & Skill Files, 2-Pane Burp Repeater + AI Audit, Terminal Dock
- `/intercept` — Burp 8080/8085 Feed, XML/JSON/HAR Inspector, Playwright Browser DOM XSS Studio, Recon Tools
- `/arsenal` — Specialist Agents, Skills Matrix & 6 Elite Probers, Kali Tools Synthesizer, CLI Engines, MCP, Sandbox
- `/system` — AI Models Catalog, LLM Routing Policy, Diagnostics & Readiness, Install Plan, Masked API Keys & Settings

## Commands
```bash
npm run dev      # Development (:3000)
npm run lint     # ESLint
npx tsc --noEmit # TypeScript verification
npm run build    # Production build (:3000)
```
