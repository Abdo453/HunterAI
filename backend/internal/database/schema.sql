-- ====================================================================
-- ARTEX-Pro Enterprise Database Schema (PostgreSQL 16+)
-- ====================================================================

CREATE TABLE IF NOT EXISTS engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(32) NOT NULL UNIQUE,
    target_url TEXT NOT NULL,
    authorized_scope TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'ACTIVE',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    root_url TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    kind VARCHAR(48) NOT NULL, -- SUBDOMAIN, IP, PORT, ENDPOINT, API, TECH
    value TEXT NOT NULL,
    attributes JSONB DEFAULT '{}'::jsonb,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_id, kind, value)
);

CREATE TABLE IF NOT EXISTS asset_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID REFERENCES asset_nodes(id) ON DELETE CASCADE,
    target_id UUID REFERENCES asset_nodes(id) ON DELETE CASCADE,
    relation VARCHAR(48) NOT NULL, -- RESOLVES_TO, LISTENS_ON, EXPOSES, ROUTES_TO
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    agent_role VARCHAR(32) NOT NULL, -- PLANNER, RECON, WEB, NETWORK, ADJUDICATOR
    title TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
    priority INT DEFAULT 5,
    input_context JSONB DEFAULT '{}'::jsonb,
    output_summary JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    vuln_class VARCHAR(128) NOT NULL,
    severity VARCHAR(24) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence NUMERIC(4, 2) DEFAULT 0.0,
    cvss_score NUMERIC(4, 2) DEFAULT 0.0,
    title TEXT NOT NULL,
    endpoint TEXT DEFAULT '',
    evidence TEXT,
    poc_script TEXT,
    poc_details JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(24) DEFAULT 'CANDIDATE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) ON DELETE CASCADE,
    actor VARCHAR(64) NOT NULL,
    action TEXT NOT NULL,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Safe additive column migrations for pre-existing databases
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE engagements ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE asset_nodes ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE asset_nodes ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES targets(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence NUMERIC(4, 2) DEFAULT 0.0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score NUMERIC(4, 2) DEFAULT 0.0;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS endpoint TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS poc_script TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS poc_details JSONB DEFAULT '{}'::jsonb;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR(24) DEFAULT 'CANDIDATE';
ALTER TABLE findings ALTER COLUMN status SET DEFAULT 'CANDIDATE';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_targets_engagement_id ON targets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_asset_nodes_target_id ON asset_nodes(target_id);
CREATE INDEX IF NOT EXISTS idx_tasks_engagement_created ON tasks(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_engagement_cvss ON findings(engagement_id, cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_engagement_created ON audit_logs(engagement_id, created_at DESC);
