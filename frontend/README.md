# ARTEX-Pro Modern Next.js 15 Frontend Dashboard

Interactive, high-performance web dashboard for the **ARTEX-Pro Autonomous Multi-Agent Security Platform**.

## Architecture
- **Framework**: Next.js 15 (App Router) + React 19 + TypeScript
- **Styling**: Tailwind CSS + Cyberpunk Dark UI Theme
- **Data Flow**: Connects to ARTEX-Pro Go REST API (`http://127.0.0.1:7071/api/v1`)
- **Database Engine**: Persistent PostgreSQL 16+ relational schema (`asset_nodes`, `engagements`, `findings`)

## Quick Start
```bash
# Install dependencies
npm install

# Run development server (:3000)
npm run dev

# Build for production
npm run build
npm start
```

## Features
- **Real-Time Dual Attack Graph**: Explores discovered subdomains, HTTP status codes, web technologies, and target endpoints.
- **Vulnerability Dossier & 7-Question Gate**: Displays triaged findings with CVSS scores and reproducible PoCs.
- **One-Click Mission Dispatch**: Directly triggers autonomous Goroutine agent pipelines from the top navigation bar.
- **Live Terminal & Activity Stream**: Real-time log monitoring of active Go agent execution.
