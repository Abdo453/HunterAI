"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Crosshair,
  Shield,
  CheckSquare,
  Scale,
  BookmarkCheck,
  Plus,
  RefreshCw,
  ShieldCheck,
  AlertCircle,
} from "lucide-react";
import { usePlatform } from "@/lib/platform-context";
import { SevenGateEvaluation } from "@/lib/api-types";
import { useI18n } from "@/lib/i18n";
import TargetPresetStrip from "@/components/TargetPresetStrip";
import { TargetPreset } from "@/lib/target-presets";

interface ChecklistItem {
  item_id: string;
  title: string;
  phase?: string;
  description?: string;
  checked: boolean;
}

interface ChecklistCategory {
  category_id: string;
  category_title: string;
  description?: string;
  items: ChecklistItem[];
}

interface RedTeamPolicyState {
  active?: boolean;
  valid_signature?: boolean;
  current_profile?: string;
  grant?: {
    grant_id?: string;
    authorized_by?: string;
    scope?: string[];
    scope_targets?: Array<{ value?: string; kind?: string } | string>;
    valid?: boolean;
    expires_at?: string;
    not_after?: string;
  } | null;
  hard_invariants?: Array<{ action: string; desc: string }>;
}

interface LeadItem {
  lead_id?: string;
  id?: string;
  skill?: string;
  evidence?: string;
  priority?: string;
  status?: string;
}

function formatScopeTargets(grant: NonNullable<RedTeamPolicyState["grant"]>): string {
  if (Array.isArray(grant.scope) && grant.scope.length > 0) {
    return grant.scope.join(", ");
  }
  if (Array.isArray(grant.scope_targets) && grant.scope_targets.length > 0) {
    return grant.scope_targets
      .map((item) => (typeof item === "string" ? item : item?.value || ""))
      .filter(Boolean)
      .join(", ");
  }
  return "—";
}

export default function OperationsPage() {
  const {
    engagements,
    selectedEngagement,
    targetDomain,
    selectEngagement,
    refreshNow,
    isLoading,
    apiJson,
  } = usePlatform();
  const { t } = useI18n();

  // Target CRUD + Validator
  const [targetName, setTargetName] = useState<string>("");
  const [targetUrl, setTargetUrl] = useState<string>("");
  const [inScopeCsv, setInScopeCsv] = useState<string>("");
  const [outScopeCsv, setOutScopeCsv] = useState<string>("");
  const [targetMsg, setTargetMsg] = useState<string>("");
  const [targetMsgError, setTargetMsgError] = useState<boolean>(false);
  const [probeUrl, setProbeUrl] = useState<string>("");
  const [scopeCheck, setScopeCheck] = useState<{ allowed?: boolean; reason?: string } | null>(null);

  // Red Team Grant
  const [rtState, setRtState] = useState<RedTeamPolicyState | null>(null);
  const [grantScope, setGrantScope] = useState<string>("");
  const [grantAuth, setGrantAuth] = useState<string>("");
  const [grantMsg, setGrantMsg] = useState<string>("");
  const [grantError, setGrantError] = useState<boolean>(false);

  // Checklists
  const [checklists, setChecklists] = useState<ChecklistCategory[]>([]);
  const [checklistProgress, setChecklistProgress] = useState<number>(0);

  // 7-Question Gate (with canonical recommendation, reproducibility, severity & proof_payload)
  const [gateTitle, setGateTitle] = useState<string>("");
  const [gateAsset, setGateAsset] = useState<string>("");
  const [gatePoc, setGatePoc] = useState<string>("");
  const [gateImpact, setGateImpact] = useState<string>("");
  const [gateRepro, setGateRepro] = useState<string>("");
  const [gateRecommendation, setGateRecommendation] = useState<string>("");
  const [gateSeverity, setGateSeverity] = useState<string>("high");
  const [gateClass, setGateClass] = useState<string>("idor");
  const [gateProofJson, setGateProofJson] = useState<string>("");
  const [gateError, setGateError] = useState<string>("");
  const [gateResult, setGateResult] = useState<SevenGateEvaluation | null>(null);

  // Lead Board
  const [leadTarget, setLeadTarget] = useState<string>("example.com");
  const [leads, setLeads] = useState<LeadItem[]>([]);
  const [leadCounts, setLeadCounts] = useState<Record<string, number>>({});
  const [newLeadSkill, setNewLeadSkill] = useState<string>("hunt-idor");
  const [newLeadEvidence, setNewLeadEvidence] = useState<string>("");

  const loadAll = useCallback(async () => {
    const lt = selectedEngagement?.target || targetDomain || "example.com";
    const [rtRes, chkRes, lbRes] = await Promise.all([
      apiJson<RedTeamPolicyState>("/api/control/redteam-policy"),
      apiJson<{ categories?: ChecklistCategory[]; progress_percent?: number }>("/api/control/checklists"),
      apiJson<{ leads?: LeadItem[]; counts?: Record<string, number>; target?: string }>(
        `/api/control/lead-board?target=${encodeURIComponent(lt)}`
      ),
    ]);
    if (rtRes.ok && rtRes.data) setRtState(rtRes.data);
    if (chkRes.ok && chkRes.data) {
      setChecklists(Array.isArray(chkRes.data.categories) ? chkRes.data.categories : []);
      setChecklistProgress(Number(chkRes.data.progress_percent || 0));
    }
    if (lbRes.ok && lbRes.data) {
      setLeads(Array.isArray(lbRes.data.leads) ? lbRes.data.leads : []);
      setLeadCounts(lbRes.data.counts || {});
      if (lbRes.data.target) setLeadTarget(lbRes.data.target);
    }
  }, [apiJson, selectedEngagement?.target, targetDomain]);

  useEffect(() => {
    if (!isLoading || selectedEngagement) {
      void loadAll();
    }
  }, [isLoading, selectedEngagement, loadAll]);

  // Single deduplicated save call — /api/control/targets/save already upserts the engagement
  const handleSaveTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setTargetMsg("");
    setTargetMsgError(false);
    const cleanUrl = targetUrl.trim();
    if (!cleanUrl) {
      setTargetMsgError(true);
      setTargetMsg(t("nav.scopeInvalidEmpty"));
      return;
    }
    const inScope = inScopeCsv.split(",").map((s) => s.trim()).filter(Boolean);
    const outScope = outScopeCsv.split(",").map((s) => s.trim()).filter(Boolean);

    const res = await apiJson<{ ok?: boolean; engagement_id?: string }>("/api/control/targets/save", {
      method: "POST",
      body: {
        name: targetName.trim() || cleanUrl,
        url: cleanUrl,
        description: t("targets.savedFromOps"),
        in_scope: inScope.length ? inScope : [cleanUrl],
        out_of_scope: outScope,
      },
    });
    if (!res.ok) {
      setTargetMsgError(true);
      setTargetMsg(res.error || t("common.error"));
      return;
    }
    setTargetName("");
    setTargetUrl("");
    setInScopeCsv("");
    setOutScopeCsv("");
    setTargetMsgError(false);
    setTargetMsg(t("targets.savedSuccess"));
    await refreshNow();
    if (res.data?.engagement_id) {
      await selectEngagement(res.data.engagement_id);
    }
  };

  const handleValidateScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!probeUrl.trim()) return;
    const res = await apiJson<{ allowed?: boolean; reason?: string }>("/api/control/targets/validate-scope", {
      method: "POST",
      body: {
        target_url: probeUrl.trim(),
        in_scope: selectedEngagement?.in_scope,
        out_of_scope: selectedEngagement?.out_of_scope,
      },
    });
    if (res.ok && res.data) {
      setScopeCheck(res.data);
    } else if (res.error) {
      setScopeCheck({ allowed: false, reason: res.error });
    }
  };

  const handleIssueGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    setGrantMsg("");
    setGrantError(false);
    const res = await apiJson<{ grant_id?: string }>("/api/control/redteam-policy/issue", {
      method: "POST",
      body: { scope: grantScope.trim(), authorized_by: grantAuth.trim(), days: 7 },
    });
    if (res.ok) {
      setGrantError(false);
      setGrantMsg(t("redteam.grantIssued", { id: res.data?.grant_id || "HMAC" }));
    } else {
      setGrantError(true);
      setGrantMsg(res.error || t("common.error"));
    }
    await loadAll();
  };

  const handleRevokeGrant = async () => {
    const res = await apiJson("/api/control/redteam-policy/revoke", { method: "POST" });
    setGrantError(!res.ok);
    setGrantMsg(res.ok ? t("redteam.grantRevoked") : res.error || t("common.error"));
    await loadAll();
  };

  const toggleChecklist = async (itemId: string, checked: boolean) => {
    await apiJson("/api/control/checklists/toggle", {
      method: "POST",
      body: { item_id: itemId, checked },
    });
    await loadAll();
  };

  const evaluateSevenGate = async (e: React.FormEvent) => {
    e.preventDefault();
    setGateError("");
    let proofPayload: Record<string, unknown> | undefined;
    if (gateProofJson.trim()) {
      try {
        const parsed = JSON.parse(gateProofJson.trim()) as unknown;
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          proofPayload = parsed as Record<string, unknown>;
        } else {
          setGateError(t("redteam.proofJsonInvalid"));
          return;
        }
      } catch {
        setGateError(t("redteam.proofJsonInvalid"));
        return;
      }
    }

    const res = await apiJson<SevenGateEvaluation>("/api/control/seven-gate/evaluate", {
      method: "POST",
      body: {
        title: gateTitle.trim(),
        asset: gateAsset.trim(),
        poc: gatePoc.trim(),
        impact: gateImpact.trim(),
        reproducibility: gateRepro.trim() || undefined,
        recommendation: gateRecommendation.trim() || undefined,
        severity: gateSeverity,
        vulnerability_class: gateClass,
        in_scope: selectedEngagement?.in_scope,
        ...(proofPayload ? { proof_payload: proofPayload } : {}),
      },
    });
    if (res.ok && res.data) {
      setGateResult(res.data);
    } else {
      setGateError(res.error || t("common.error"));
    }
  };

  const handleAddLead = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLeadEvidence.trim()) return;
    await apiJson("/api/control/lead-board/add", {
      method: "POST",
      body: {
        target: selectedEngagement?.target || leadTarget || "example.com",
        skill: newLeadSkill,
        evidence: newLeadEvidence.trim(),
        priority: "high",
      },
    });
    setNewLeadEvidence("");
    await loadAll();
  };

  const touchLeadStatus = async (leadId: string, status: string) => {
    await apiJson("/api/control/lead-board/touch", {
      method: "POST",
      body: { target: selectedEngagement?.target || leadTarget || "example.com", lead_id: leadId, status },
    });
    await loadAll();
  };

  return (
    <div className="space-y-5">
      {/* Targets & Scope Validator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-7 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Crosshair className="w-4 h-4 text-sentinel-primary" />
            <h1 className="text-sm font-semibold text-ink-primary">{t("targets.title")}</h1>
          </div>

          <TargetPresetStrip
            testId="operations-target-presets"
            heading={t("targets.quickFillTitle")}
            subtitle={t("targets.quickFillHint")}
            activeTarget={targetUrl}
            onSelect={(preset: TargetPreset) => {
              setTargetName(preset.label);
              setTargetUrl(preset.target);
              setInScopeCsv(preset.inScope.join(", "));
              setOutScopeCsv("");
              setTargetMsg("");
              setTargetMsgError(false);
            }}
          />

          <form onSubmit={handleSaveTarget} className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
            <input
              type="text"
              value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
              placeholder={t("targets.projectName")}
              aria-label={t("targets.projectName")}
              className="h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
            />
            <input
              type="text"
              dir="ltr"
              list="target-example-presets"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder={t("targets.targetUrl")}
              aria-label={t("targets.targetUrl")}
              className="ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />
            <input
              type="text"
              dir="ltr"
              value={inScopeCsv}
              onChange={(e) => setInScopeCsv(e.target.value)}
              placeholder={`${t("targets.inScopeDomains")} (CSV)`}
              aria-label={t("targets.inScopeDomains")}
              className="ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />
            <input
              type="text"
              dir="ltr"
              value={outScopeCsv}
              onChange={(e) => setOutScopeCsv(e.target.value)}
              placeholder={`${t("targets.outScopeDomains")} (CSV)`}
              aria-label={t("targets.outScopeDomains")}
              className="ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />
            <div className="sm:col-span-2 flex items-center gap-3">
              <button
                type="submit"
                className="min-h-[44px] sm:min-h-[36px] px-4 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold hover:opacity-90"
              >
                {t("targets.saveTarget")}
              </button>
              {targetMsg && (
                <span
                  role={targetMsgError ? "alert" : "status"}
                  className={`font-mono ${targetMsgError ? "text-sentinel-danger" : "text-sentinel-success"}`}
                >
                  {targetMsg}
                </span>
              )}
            </div>
          </form>

          <div className="space-y-1.5 max-h-52 overflow-y-auto pt-2 border-t border-border-subtle">
            {engagements.length === 0 ? (
              <div className="text-xs text-ink-muted py-3">{t("targets.emptyTargets")}</div>
            ) : (
              engagements.map((eng, idx) => (
                <div key={`${eng.id || eng.name || "eng"}-${idx}`} className="p-2.5 rounded bg-elevated border border-border-subtle flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="min-w-0">
                    <div className="font-semibold text-ink-primary truncate">{eng.name}</div>
                    <div className="font-mono text-[11px] text-ink-muted ltr-isolate truncate">
                      {eng.target} · {eng.in_scope.join(", ")}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => void selectEngagement(eng.id)}
                    className={`h-7 px-2.5 rounded border text-xs ${
                      selectedEngagement?.id === eng.id
                        ? "border-sentinel-success bg-sentinel-success/15 text-sentinel-success"
                        : "border-border-subtle bg-inset text-ink-secondary hover:border-border-strong"
                    }`}
                  >
                    {selectedEngagement?.id === eng.id ? t("states.active") : t("common.enable")}
                  </button>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="lg:col-span-5 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Shield className="w-4 h-4 text-sentinel-success" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("targets.validatorTitle")}</h2>
          </div>
          <p className="text-xs text-ink-muted">{t("targets.validatorDesc")}</p>

          <form onSubmit={handleValidateScope} className="flex gap-2">
            <input
              type="text"
              dir="ltr"
              value={probeUrl}
              onChange={(e) => setProbeUrl(e.target.value)}
              placeholder={t("targets.testUrlPlaceholder")}
              aria-label={t("targets.testUrlPlaceholder")}
              className="ltr-isolate flex-1 h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-xs text-ink-primary"
            />
            <button
              type="submit"
              className="min-h-[44px] sm:min-h-[36px] px-3 rounded bg-elevated border border-border-strong text-xs font-semibold text-ink-primary hover:border-sentinel-primary"
            >
              {t("targets.validateScope")}
            </button>
          </form>

          {scopeCheck && (
            <div
              className={`p-3 rounded border text-xs space-y-1 ${
                scopeCheck.allowed
                  ? "border-sentinel-success/40 bg-sentinel-success/10 text-sentinel-success"
                  : "border-sentinel-danger/40 bg-sentinel-danger/10 text-sentinel-danger"
              }`}
            >
              <div className="font-mono font-semibold">
                {scopeCheck.allowed ? t("targets.scopeMatched") : t("targets.scopeOutside")}
              </div>
              <div>{scopeCheck.reason}</div>
            </div>
          )}
        </section>
      </div>

      {/* Red Team HMAC Grant + Hard Invariants */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <h2 className="text-sm font-semibold text-ink-primary">{t("redteam.grantCardTitle")}</h2>
            <div className="flex items-center gap-1.5">
              {rtState?.valid_signature && (
                <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-sentinel-success/15 text-sentinel-success border border-sentinel-success/35">
                  <ShieldCheck className="w-3 h-3" />
                  <span>{t("redteam.signatureValid")}</span>
                </span>
              )}
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-sentinel-warning/15 text-sentinel-warning border border-sentinel-warning/35">
                {rtState?.current_profile || "STANDARD"}
              </span>
            </div>
          </div>

          {rtState?.grant && rtState.grant.grant_id && (
            <div className="p-3 rounded bg-elevated border border-border-subtle text-xs space-y-1 font-mono ltr-isolate">
              <div className="text-sentinel-success">
                {rtState.grant.grant_id} · {rtState.grant.authorized_by}
              </div>
              <div className="text-ink-muted">
                {t("redteam.grantScope")}: {formatScopeTargets(rtState.grant)} · {t("redteam.grantExpires")}:{" "}
                {rtState.grant.not_after || rtState.grant.expires_at || "—"}
              </div>
            </div>
          )}

          <form onSubmit={handleIssueGrant} className="space-y-2 text-xs">
            <input
              type="text"
              dir="ltr"
              required
              value={grantScope}
              onChange={(e) => setGrantScope(e.target.value)}
              placeholder={t("redteam.scopePlaceholder")}
              aria-label={t("redteam.scopePlaceholder")}
              className="ltr-isolate w-full h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />
            <input
              type="text"
              required
              value={grantAuth}
              onChange={(e) => setGrantAuth(e.target.value)}
              placeholder={t("redteam.authPlaceholder")}
              aria-label={t("redteam.authPlaceholder")}
              className="w-full h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
            />
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="submit"
                className="min-h-[44px] sm:min-h-[36px] px-3 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold"
              >
                {t("redteam.issueGrant")}
              </button>
              <button
                type="button"
                onClick={() => void handleRevokeGrant()}
                className="min-h-[44px] sm:min-h-[36px] px-3 rounded border border-sentinel-danger/40 bg-sentinel-danger/10 text-sentinel-danger font-semibold"
              >
                {t("redteam.revokeGrant")}
              </button>
              {grantMsg && (
                <span className={`font-mono ${grantError ? "text-sentinel-danger" : "text-sentinel-success"}`}>
                  {grantMsg}
                </span>
              )}
            </div>
          </form>
        </section>

        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
            <h2 className="text-sm font-semibold text-ink-primary">{t("redteam.invariantsTitle")}</h2>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-sentinel-danger/15 text-sentinel-danger border border-sentinel-danger/35">
              {t("redteam.invariantsBadge")}
            </span>
          </div>

          <div className="space-y-1.5 max-h-56 overflow-y-auto text-xs">
            {(rtState?.hard_invariants || []).map((inv, idx) => (
              <div key={`${inv.action || "inv"}-${idx}`} className="p-2 rounded bg-inset border border-border-subtle flex items-start gap-2">
                <span className="font-mono font-semibold text-sentinel-danger shrink-0">{inv.action}</span>
                <span className="text-ink-secondary">{inv.desc}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* 7-Question Gate + Lead Board */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-border-subtle">
            <Scale className="w-4 h-4 text-sentinel-warning" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("redteam.sevenGateTitle")}</h2>
          </div>

          <form onSubmit={evaluateSevenGate} className="space-y-2 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input
                type="text"
                required
                value={gateTitle}
                onChange={(e) => setGateTitle(e.target.value)}
                placeholder={t("redteam.findingTitlePlaceholder")}
                aria-label={t("redteam.findingTitlePlaceholder")}
                className="h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
              />
              <input
                type="text"
                dir="ltr"
                required
                value={gateAsset}
                onChange={(e) => setGateAsset(e.target.value)}
                placeholder={t("redteam.findingAssetPlaceholder")}
                aria-label={t("redteam.findingAssetPlaceholder")}
                className="ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <select
                value={gateClass}
                onChange={(e) => setGateClass(e.target.value)}
                aria-label={t("redteam.vulnClassLabel")}
                className="h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
              >
                {["idor", "ssrf", "xss", "sqli", "auth_bypass", "rce", "oauth"].map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <select
                value={gateSeverity}
                onChange={(e) => setGateSeverity(e.target.value)}
                aria-label={t("common.severity")}
                className="h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
              >
                {["critical", "high", "medium", "low", "info"].map((sev) => (
                  <option key={sev} value={sev}>{sev}</option>
                ))}
              </select>
              <input
                type="text"
                required
                value={gateImpact}
                onChange={(e) => setGateImpact(e.target.value)}
                placeholder={t("redteam.findingImpactPlaceholder")}
                aria-label={t("redteam.findingImpactPlaceholder")}
                className="h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input
                type="text"
                value={gateRepro}
                onChange={(e) => setGateRepro(e.target.value)}
                placeholder={t("redteam.reproPlaceholder")}
                aria-label={t("redteam.reproPlaceholder")}
                className="h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
              />
              <input
                type="text"
                value={gateRecommendation}
                onChange={(e) => setGateRecommendation(e.target.value)}
                placeholder={t("redteam.recommendationPlaceholder")}
                aria-label={t("redteam.recommendationPlaceholder")}
                className="h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
              />
            </div>

            <textarea
              rows={2}
              required
              value={gatePoc}
              onChange={(e) => setGatePoc(e.target.value)}
              placeholder={t("redteam.findingPocPlaceholder")}
              aria-label={t("redteam.findingPocPlaceholder")}
              className="w-full p-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
            />

            <textarea
              rows={2}
              dir="ltr"
              value={gateProofJson}
              onChange={(e) => setGateProofJson(e.target.value)}
              placeholder={t("redteam.proofPayloadPlaceholder")}
              aria-label={t("redteam.proofPayloadPlaceholder")}
              className="ltr-isolate w-full p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-primary"
            />

            {gateError && (
              <div role="alert" className="p-2 rounded bg-sentinel-danger/10 border border-sentinel-danger/40 text-sentinel-danger flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{gateError}</span>
              </div>
            )}

            <button
              type="submit"
              className="min-h-[44px] sm:min-h-[36px] px-4 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold"
            >
              {t("redteam.evaluateGate")}
            </button>
          </form>

          {gateResult && (
            <div
              className={`p-3 rounded border text-xs space-y-1.5 ${
                gateResult.passed
                  ? "border-sentinel-success/40 bg-sentinel-success/10 text-sentinel-success"
                  : "border-sentinel-danger/40 bg-sentinel-danger/10 text-sentinel-danger"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono font-semibold">
                <span>
                  {gateResult.passed ? t("redteam.gatePass") : t("redteam.gateFail")} ·{" "}
                  {t("redteam.scoreLabel")}: {gateResult.score}
                </span>
                <div className="flex items-center gap-1.5">
                  {gateResult.canonical_verdict && (
                    <span className="px-1.5 py-0.5 rounded bg-surface border border-border-subtle text-ink-primary">
                      {gateResult.canonical_verdict}
                    </span>
                  )}
                  {gateResult.proof_strength && (
                    <span className="px-1.5 py-0.5 rounded bg-surface border border-border-subtle text-sentinel-primary">
                      {gateResult.proof_strength}
                    </span>
                  )}
                </div>
              </div>
              {gateResult.triage_statement && (
                <div className="text-ink-primary">{gateResult.triage_statement}</div>
              )}
              {Array.isArray(gateResult.missing_items) && gateResult.missing_items.length > 0 && (
                <div className="text-ink-secondary">
                  {t("redteam.missingLabel")}: {gateResult.missing_items.join(", ")}
                </div>
              )}
            </div>
          )}
        </section>

        <section className="lg:col-span-6 sentinel-surface p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <BookmarkCheck className="w-4 h-4 text-sentinel-primary" />
              <h2 className="text-sm font-semibold text-ink-primary">{t("redteam.leadBoardTitle")}</h2>
            </div>
            <button
              type="button"
              onClick={() => void loadAll()}
              className="h-7 px-2 rounded border border-border-subtle bg-elevated text-xs text-ink-primary flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" />
              <span>{t("common.refresh")}</span>
            </button>
          </div>

          <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
            {Object.entries(leadCounts).map(([st, cnt]) => (
              <span key={st} className="px-2 py-0.5 rounded bg-elevated border border-border-subtle text-ink-secondary tabular-nums">
                {st}: {cnt}
              </span>
            ))}
          </div>

          <form onSubmit={handleAddLead} className="flex flex-wrap gap-2 text-xs">
            <input
              type="text"
              dir="ltr"
              value={newLeadSkill}
              onChange={(e) => setNewLeadSkill(e.target.value)}
              placeholder={t("redteam.leadSkillPlaceholder")}
              aria-label={t("redteam.leadSkillPlaceholder")}
              className="ltr-isolate w-28 h-8 px-2 rounded bg-inset border border-border-subtle font-mono"
            />
            <input
              type="text"
              value={newLeadEvidence}
              onChange={(e) => setNewLeadEvidence(e.target.value)}
              placeholder={t("redteam.leadEvidencePlaceholder")}
              aria-label={t("redteam.leadEvidencePlaceholder")}
              className="flex-1 min-w-[160px] h-8 px-2.5 rounded bg-inset border border-border-subtle"
            />
            <button
              type="submit"
              className="h-8 px-2.5 rounded bg-elevated border border-border-strong text-ink-primary flex items-center gap-1"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{t("redteam.newLead")}</span>
            </button>
          </form>

          <div className="space-y-1.5 max-h-52 overflow-y-auto text-xs">
            {leads.length === 0 ? (
              <div className="py-6 text-center text-ink-muted">{t("common.noData")}</div>
            ) : (
              leads.map((ld, idx) => {
                const lid = ld.lead_id || ld.id || String(idx);
                return (
                  <div key={`${lid}-${idx}`} className="p-2.5 rounded bg-elevated border border-border-subtle space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-sentinel-primary">{ld.skill}</span>
                      <span className="font-mono text-[11px] text-ink-muted">{ld.status}</span>
                    </div>
                    <div className="text-ink-secondary">{ld.evidence}</div>
                    <div className="flex flex-wrap gap-1">
                      {(
                        [
                          { id: "investigating", labelKey: "redteam.leadInvestigating" },
                          { id: "reported", labelKey: "redteam.leadReported" },
                          { id: "killed", labelKey: "redteam.leadKilled" },
                        ] as const
                      ).map((nextSt) => (
                        <button
                          key={nextSt.id}
                          type="button"
                          onClick={() => void touchLeadStatus(lid, nextSt.id)}
                          className="px-2 py-0.5 rounded bg-inset border border-border-subtle text-[11px] font-mono text-ink-muted hover:text-ink-primary"
                        >
                          {t(nextSt.labelKey)}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>
      </div>

      {/* Operational Security Checklists */}
      <section className="sentinel-surface p-4 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <CheckSquare className="w-4 h-4 text-sentinel-success" />
            <h2 className="text-sm font-semibold text-ink-primary">{t("redteam.checklistsTitle")}</h2>
          </div>
          <span className="text-xs font-mono tabular-nums text-sentinel-success">
            {t("redteam.checklistsProgress")}: {checklistProgress}%
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {checklists.map((cat, catIdx) => (
            <div key={`${cat.category_id || cat.category_title || "cat"}-${catIdx}`} className="p-3 rounded-md bg-inset border border-border-subtle space-y-2">
              <div className="text-xs font-semibold text-ink-primary">{cat.category_title}</div>
              <div className="space-y-1.5">
                {cat.items.map((it, itemIdx) => (
                  <label key={`${it.item_id || it.title || "item"}-${itemIdx}`} className="flex items-start gap-2 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={Boolean(it.checked)}
                      onChange={(e) => void toggleChecklist(it.item_id, e.target.checked)}
                      className="mt-0.5 rounded border-border-strong"
                    />
                    <span className={it.checked ? "line-through text-ink-muted" : "text-ink-secondary"}>
                      {it.title}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
