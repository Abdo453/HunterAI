"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Server, Plus, ShieldCheck, Fingerprint, X, Play, RefreshCw, AlertTriangle } from "lucide-react";
import { McpServerRecord } from "@/lib/api-types";
import { usePlatform } from "@/lib/platform-context";
import { useI18n } from "@/lib/i18n";
import { useFocusTrap } from "@/hooks/use-focus-trap";

/**
 * Compute deterministic SHA-256 `mcpServerFingerprint` for operator consent confirmation.
 */
async function computeMcpServerFingerprint(payload: {
  server_id: string;
  transport: string;
  command?: string;
  args?: string[];
  endpoint?: string;
}): Promise<string> {
  const canonical = JSON.stringify({
    server_id: payload.server_id.trim(),
    transport: payload.transport.trim(),
    command: (payload.command || "").trim(),
    args: payload.args || [],
    endpoint: (payload.endpoint || "").trim(),
  });

  if (typeof window !== "undefined" && window.crypto?.subtle) {
    const encoded = new TextEncoder().encode(canonical);
    const digest = await window.crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Deterministic fallback hash for non-secure test contexts
  let h1 = 0xdeadbeef ^ canonical.length;
  let h2 = 0x41c6ce57 ^ canonical.length;
  for (let i = 0; i < canonical.length; i++) {
    const ch = canonical.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  return `${(h1 >>> 0).toString(16).padStart(8, "0")}${(h2 >>> 0).toString(16).padStart(8, "0")}`.repeat(4);
}

export default function McpManagerModal() {
  const { apiJson } = usePlatform();
  const { t } = useI18n();

  const [servers, setServers] = useState<McpServerRecord[]>([]);
  const [mcpTools, setMcpTools] = useState<Array<{ name: string; description?: string }>>([]);
  const [opencodeStatus, setOpencodeStatus] = useState<Record<string, unknown> | null>(null);
  const [probing, setProbing] = useState<boolean>(false);

  // Add server + SHA-256 consent modal
  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [serverId, setServerId] = useState<string>("");
  const [serverName, setServerName] = useState<string>("");
  const [transport, setTransport] = useState<string>("stdio");
  const [command, setCommand] = useState<string>("");
  const [argsCsv, setArgsCsv] = useState<string>("");
  const [endpoint, setEndpoint] = useState<string>("");
  const [fingerprint, setFingerprint] = useState<string>("");
  const [consentConfirmed, setConsentConfirmed] = useState<boolean>(false);
  const [formError, setFormError] = useState<string>("");

  // Tool invoker
  const [invokeServerId, setInvokeServerId] = useState<string>("hunter-arsenal");
  const [invokeTool, setInvokeTool] = useState<string>("");
  const [invokeArgs, setInvokeArgs] = useState<string>("{}");
  const [invokeOut, setInvokeOut] = useState<string>("");

  const trapRef = useFocusTrap(modalOpen, () => setModalOpen(false));

  const loadMcp = useCallback(async () => {
    setProbing(true);
    const [srvR, ocR] = await Promise.all([
      apiJson<{ servers?: McpServerRecord[]; tools?: Array<{ name?: string; description?: string }> }>(
        "/api/mcp/servers"
      ),
      apiJson<Record<string, unknown>>("/api/opencode/mcp-status"),
    ]);
    setProbing(false);
    if (srvR.ok && srvR.data) {
      const list = Array.isArray(srvR.data.servers) ? srvR.data.servers : [];
      setServers(list);
      if (list[0]?.server_id) setInvokeServerId(list[0].server_id);
      if (Array.isArray(srvR.data.tools)) {
        setMcpTools(
          srvR.data.tools
            .filter((x): x is { name: string; description?: string } => Boolean(x?.name))
            .slice(0, 60)
        );
      }
    }
    if (ocR.ok && ocR.data) setOpencodeStatus(ocR.data);
  }, [apiJson]);

  useEffect(() => {
    void loadMcp();
  }, [loadMcp]);

  useEffect(() => {
    let active = true;
    const args = argsCsv
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    void computeMcpServerFingerprint({
      server_id: serverId || "new-server",
      transport,
      command,
      args,
      endpoint,
    }).then((fp) => {
      if (active) setFingerprint(fp);
    });
    return () => {
      active = false;
    };
  }, [serverId, transport, command, argsCsv, endpoint]);

  const handleRegisterServer = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    if (!serverId.trim() || !serverName.trim()) {
      setFormError(t("mcp.requiredFieldsError"));
      return;
    }
    if (!consentConfirmed) {
      setFormError(t("mcp.consentRequired"));
      return;
    }
    const args = argsCsv
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (args.some((a) => a.includes("@latest"))) {
      setFormError(t("mcp.pinnedVersionRequired"));
      return;
    }

    const res = await apiJson<{ ok?: boolean; server?: McpServerRecord }>("/api/mcp/servers", {
      method: "POST",
      body: {
        server_id: serverId.trim(),
        name: serverName.trim(),
        transport,
        command: command.trim() || null,
        args,
        endpoint: endpoint.trim() || null,
        enabled: true,
      },
    });
    if (!res.ok) {
      setFormError(res.error || t("mcp.saveFailed"));
      return;
    }
    setModalOpen(false);
    setServerId("");
    setServerName("");
    setCommand("");
    setArgsCsv("");
    setEndpoint("");
    setConsentConfirmed(false);
    await loadMcp();
  };

  const handleInvoke = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!invokeTool.trim()) return;
    let parsed: Record<string, unknown> = {};
    try {
      parsed = JSON.parse(invokeArgs || "{}") as Record<string, unknown>;
    } catch {
      setInvokeOut(t("mcp.invalidJson"));
      return;
    }
    const res = await apiJson<Record<string, unknown>>("/api/mcp/call", {
      method: "POST",
      body: {
        server_id: invokeServerId.trim() || "hunter-arsenal",
        tool_name: invokeTool.trim(),
        arguments: parsed,
      },
    });
    setInvokeOut(JSON.stringify(res.data || { ok: false, error: res.error }, null, 2));
  };

  return (
    <section
      data-testid="mcp-manager-panel"
      aria-labelledby="mcp-panel-heading"
      className="sentinel-surface p-4 space-y-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle">
        <div className="flex items-center gap-2 min-w-0">
          <Server className="w-4 h-4 text-sentinel-success shrink-0" />
          <h2 id="mcp-panel-heading" className="text-sm font-semibold text-ink-primary truncate">
            {t("mcp.title")}
          </h2>
          <span className="px-2 py-0.5 rounded-full text-[11px] font-mono tabular-nums bg-elevated border border-border-subtle text-ink-secondary">
            {servers.length}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => void loadMcp()}
            disabled={probing}
            aria-label={t("mcp.probeBtn")}
            className="h-8 px-2.5 rounded border border-border-subtle bg-elevated hover:border-border-strong text-xs text-ink-primary flex items-center gap-1"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${probing ? "animate-spin" : ""}`} />
            <span>{t("mcp.probeBtn")}</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setFormError("");
              setConsentConfirmed(false);
              setModalOpen(true);
            }}
            className="h-8 px-2.5 rounded bg-sentinel-primary text-sentinel-onAccent text-xs font-semibold flex items-center gap-1 hover:opacity-90"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t("mcp.addServer")}</span>
          </button>
        </div>
      </div>

      {/* Structured MCP Server Cards */}
      <div className="space-y-2 max-h-44 overflow-y-auto pe-1">
        {servers.length === 0 ? (
          <div className="py-4 text-center text-xs text-ink-muted">{t("mcp.emptyServers")}</div>
        ) : (
          servers.map((srv) => (
            <div
              key={srv.server_id}
              className="p-2.5 rounded bg-elevated border border-border-subtle text-xs space-y-1"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono font-semibold text-ink-primary ltr-isolate">
                  {srv.name || srv.server_id}
                </span>
                <span
                  className={`px-1.5 py-0.5 rounded border text-[10px] font-mono ${
                    srv.enabled
                      ? "bg-sentinel-success/15 text-sentinel-success border-sentinel-success/35"
                      : "bg-inset text-ink-muted border-border-subtle"
                  }`}
                >
                  {srv.enabled ? t("states.ready") : t("common.disabled")}
                </span>
              </div>
              <div className="font-mono text-[11px] text-ink-muted ltr-isolate truncate">
                {srv.transport} · {srv.endpoint || srv.command || srv.server_id}
              </div>
            </div>
          ))
        )}
      </div>

      {opencodeStatus && (
        <div className="p-2 rounded bg-inset border border-border-subtle text-[11px] font-mono text-ink-secondary flex items-center justify-between gap-2">
          <span>{t("mcp.configSource")}</span>
          <span className="text-sentinel-primary ltr-isolate">
            {String(opencodeStatus.status || opencodeStatus.server_count || t("states.ready"))}
          </span>
        </div>
      )}

      {/* Schema-Driven Tool Invoker */}
      <form onSubmit={handleInvoke} className="space-y-2 pt-2 border-t border-border-subtle text-xs">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input
            type="text"
            dir="ltr"
            value={invokeServerId}
            onChange={(e) => setInvokeServerId(e.target.value)}
            placeholder={t("mcp.serverIdPlaceholder")}
            aria-label={t("mcp.serverIdPlaceholder")}
            className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
          />
          <input
            type="text"
            dir="ltr"
            list="mcp-tool-datalist"
            value={invokeTool}
            onChange={(e) => setInvokeTool(e.target.value)}
            placeholder={t("mcp.toolNamePlaceholder")}
            aria-label={t("mcp.toolNamePlaceholder")}
            className="ltr-isolate h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
          />
          <datalist id="mcp-tool-datalist">
            {mcpTools.map((tl) => (
              <option key={tl.name} value={tl.name}>
                {tl.description || tl.name}
              </option>
            ))}
          </datalist>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            dir="ltr"
            value={invokeArgs}
            onChange={(e) => setInvokeArgs(e.target.value)}
            placeholder="{}"
            aria-label={t("mcp.argsLabel")}
            className="ltr-isolate flex-1 h-8 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
          />
          <button
            type="submit"
            className="h-8 px-3 rounded bg-elevated border border-border-strong hover:border-sentinel-primary text-ink-primary font-semibold flex items-center gap-1"
          >
            <Play className="w-3 h-3 text-sentinel-primary" />
            <span>{t("mcp.callTool")}</span>
          </button>
        </div>
      </form>

      {invokeOut && (
        <pre
          dir="ltr"
          className="ltr-isolate p-2.5 rounded bg-inset border border-border-subtle font-mono text-[11px] text-ink-secondary max-h-32 overflow-auto"
        >
          {invokeOut}
        </pre>
      )}

      {/* Register MCP Server Modal with SHA-256 Fingerprint Consent */}
      {modalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-[1px]"
          onClick={() => setModalOpen(false)}
        >
          <div
            ref={trapRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="mcp-modal-title"
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-lg rounded-xl border border-border-strong bg-surface shadow-sentinelMd overflow-hidden"
          >
            <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-sentinel-primary" />
                <h3 id="mcp-modal-title" className="text-sm font-semibold text-ink-primary">
                  {t("mcp.addServer")}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                aria-label={t("common.close")}
                className="min-h-[44px] min-w-[44px] lg:min-h-0 lg:min-w-0 lg:h-8 lg:w-8 rounded border border-border-subtle bg-elevated text-ink-primary flex items-center justify-center"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleRegisterServer} className="p-4 space-y-3 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <input
                  type="text"
                  dir="ltr"
                  required
                  value={serverId}
                  onChange={(e) => setServerId(e.target.value)}
                  placeholder={t("mcp.serverIdPlaceholder")}
                  className="ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
                />
                <input
                  type="text"
                  required
                  value={serverName}
                  onChange={(e) => setServerName(e.target.value)}
                  placeholder={t("common.name")}
                  className="h-9 px-3 rounded bg-inset border border-border-subtle text-ink-primary"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <select
                  value={transport}
                  onChange={(e) => setTransport(e.target.value)}
                  aria-label={t("mcp.transport")}
                  className="h-9 px-2.5 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
                >
                  <option value="stdio">stdio</option>
                  <option value="http">http</option>
                  <option value="sse">sse</option>
                </select>
                <input
                  type="text"
                  dir="ltr"
                  value={transport === "stdio" ? command : endpoint}
                  onChange={(e) =>
                    transport === "stdio" ? setCommand(e.target.value) : setEndpoint(e.target.value)
                  }
                  placeholder={transport === "stdio" ? t("mcp.commandLabel") : t("mcp.endpointLabel")}
                  className="ltr-isolate h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
                />
              </div>

              {transport === "stdio" && (
                <input
                  type="text"
                  dir="ltr"
                  value={argsCsv}
                  onChange={(e) => setArgsCsv(e.target.value)}
                  placeholder={t("mcp.argsCsvPlaceholder")}
                  className="ltr-isolate w-full h-9 px-3 rounded bg-inset border border-border-subtle font-mono text-ink-primary"
                />
              )}

              {/* SHA-256 mcpServerFingerprint Consent Box */}
              <div className="p-3 rounded-md bg-inset border border-sentinel-warning/40 space-y-2">
                <div className="flex items-center gap-1.5 text-sentinel-warning font-semibold">
                  <Fingerprint className="w-4 h-4 shrink-0" />
                  <span>{t("mcp.fingerprintTitle")}</span>
                </div>
                <div
                  dir="ltr"
                  data-testid="mcp-server-fingerprint"
                  className="ltr-isolate font-mono text-[11px] text-ink-primary break-all bg-surface p-2 rounded border border-border-subtle"
                >
                  sha256:{fingerprint}
                </div>
                <label className="flex items-start gap-2 cursor-pointer text-ink-secondary">
                  <input
                    type="checkbox"
                    checked={consentConfirmed}
                    onChange={(e) => setConsentConfirmed(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>{t("mcp.fingerprintConsentLabel")}</span>
                </label>
              </div>

              {formError && (
                <div
                  role="alert"
                  className="p-2.5 rounded bg-sentinel-danger/15 border border-sentinel-danger/40 text-sentinel-danger flex items-center gap-1.5"
                >
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="min-h-[36px] px-3 rounded border border-border-subtle bg-elevated text-ink-secondary hover:text-ink-primary"
                >
                  {t("common.cancel")}
                </button>
                <button
                  type="submit"
                  className="min-h-[36px] px-4 rounded bg-sentinel-primary text-sentinel-onAccent font-semibold hover:opacity-90"
                >
                  {t("common.confirm")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}
