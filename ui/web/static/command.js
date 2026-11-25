/* HunterAI Command Center JS — Hardened DOM updates & visibility-aware polling */

(function () {
  "use strict";

  let isBusy = false;
  let cachedSettings = null;

  function notify(msg, tone) {
    if (window.HunterCore && typeof window.HunterCore.toast === "function") {
      window.HunterCore.toast(msg, tone || "info");
    }
  }

  function syncExecStatus(overrideAllowExec) {
    const execChip = document.getElementById("exec-status");
    if (!execChip) return;
    const chk = document.getElementById("exec-chk");
    const allowed = typeof overrideAllowExec === "boolean"
      ? overrideAllowExec
      : (chk ? Boolean(chk.checked) : true);
    execChip.style.display = allowed ? "inline-flex" : "none";
  }

  function applyProviderDefaultModel(providerName) {
    if (!cachedSettings) return;
    const mEl = document.getElementById("model-input");
    if (!mEl) return;
    const defaults = cachedSettings.default_models || {};
    const nextDefault = defaults[providerName] || cachedSettings.default_model || "";
    if (nextDefault) {
      mEl.placeholder = nextDefault;
      if (!mEl.value) mEl.value = nextDefault;
    }
  }

  function setupInput() {
    const inp = document.getElementById("chat-input");
    if (!inp) return;
    inp.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        const form = document.getElementById("chat-composer");
        if (form) form.requestSubmit ? form.requestSubmit() : sendChat(e);
      }
    });
    inp.addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = Math.min(this.scrollHeight, 140) + "px";
    });
  }

  async function loadSettings() {
    try {
      const res = await fetch("/api/settings");
      if (!res.ok) return;
      const d = await res.json();
      cachedSettings = d;
      const box = document.getElementById("provider-status");
      if (!box) return;
      box.textContent = "";

      const keysMap = d.keys && typeof d.keys === "object" ? d.keys : {};
      let statusEntries = [];
      if (Array.isArray(d.providers)) {
        statusEntries = d.providers.map((prov) => {
          const info = keysMap[prov];
          const configured = typeof info === "boolean"
            ? info
            : Boolean(info && (info.configured || info.key_masked));
          return [prov, configured, info];
        });
      } else if (d.providers && typeof d.providers === "object") {
        statusEntries = Object.entries(d.providers).map(([k, v]) => [k, Boolean(v), null]);
      } else {
        statusEntries = Object.entries(keysMap).map(([k, info]) => [
          k,
          typeof info === "boolean" ? info : Boolean(info && (info.configured || info.key_masked)),
          info,
        ]);
      }

      for (const [k, configured, info] of statusEntries) {
        const chip = document.createElement("span");
        const isLocal = k === "ollama";
        if (isLocal && !configured) {
          chip.className = "status-chip ltr-isolate";
          chip.textContent = `${k}: Local (no key)`;
        } else {
          chip.className = "status-chip ltr-isolate " + (configured ? "ok" : "miss");
          const masked = info && info.key_masked ? ` (${info.key_masked})` : "";
          chip.textContent = `${k}: ${configured ? "Ready" : "Missing"}${masked}`;
        }
        box.appendChild(chip);
        box.appendChild(document.createTextNode(" "));
      }

      const sel = document.getElementById("provider-select");
      let activeProvider = d.default_provider || "";
      if (!activeProvider) {
        const firstConfigured = statusEntries.find(([, ok]) => ok);
        if (firstConfigured) activeProvider = firstConfigured[0];
      }
      if (sel && activeProvider && [...sel.options].some((o) => o.value === activeProvider)) {
        sel.value = activeProvider;
      }

      applyProviderDefaultModel(sel ? sel.value : activeProvider);
      syncExecStatus(typeof d.allow_exec === "boolean" ? d.allow_exec : undefined);
    } catch (_) {}
  }

  async function saveSettings() {
    const prov = document.getElementById("provider-select")?.value || "nvidia";
    const key = document.getElementById("api-key-input")?.value.trim() || "";
    const model = document.getElementById("model-input")?.value.trim() || "";
    const status = document.getElementById("save-status");
    if (status) {
      status.style.color = "var(--cyan)";
      status.textContent = "Saving to .env...";
    }

    const payload = { provider: prov, api_key: key, model: model };
    if (key) {
      payload[prov] = key;
    }

    try {
      const res = await fetch("/api/settings/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const d = await res.json().catch(() => ({}));
      const savedOk = res.ok && (d.status === "saved" || Boolean(d.ok));
      if (savedOk) {
        if (status) {
          status.style.color = "var(--emerald)";
          status.textContent = d.note || "Saved to .env & active now";
        }
        const apiKeyEl = document.getElementById("api-key-input");
        if (apiKeyEl) apiKeyEl.value = "";
        notify("Settings saved to .env", "success");
        loadSettings();
      } else {
        const errText = d.error || d.detail || ("Save failed (HTTP " + res.status + ")");
        if (status) {
          status.style.color = "var(--red)";
          status.textContent = errText;
        }
        notify(errText, "error");
      }
    } catch (e) {
      if (status) {
        status.style.color = "var(--red)";
        status.textContent = "Error: " + (e && e.message ? e.message : String(e));
      }
    }
  }

  async function sendChat(e) {
    if (e && typeof e.preventDefault === "function") e.preventDefault();
    if (isBusy) return false;
    const inp = document.getElementById("chat-input");
    const msg = (inp?.value || "").trim();
    if (!msg) return false;

    isBusy = true;
    inp.value = "";
    inp.style.height = "auto";
    appendUserMsg(msg);
    const aiMsg = appendAIMsg("Thinking & executing...");

    const target = document.getElementById("target-input")?.value.trim() || "";
    const scopeRaw = document.getElementById("scope-input")?.value.trim() || "";
    const scope = scopeRaw ? scopeRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];
    const provider = document.getElementById("provider-select")?.value || "auto";
    const model = document.getElementById("model-input")?.value.trim() || "";
    const authorized = Boolean(document.getElementById("authorized-chk")?.checked);
    const allowExec = Boolean(document.getElementById("exec-chk")?.checked);

    const platformState = window.HunterPlatform && typeof window.HunterPlatform.getState === "function"
      ? window.HunterPlatform.getState()
      : null;
    const ctx = (platformState && platformState.context) || {};

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: msg,
          target: target,
          scope: scope,
          provider: provider,
          model: model,
          authorized: authorized,
          allow_exec: allowExec,
          engagement_id: ctx.active_engagement_id || ctx.engagement_id || "",
          run_id: ctx.active_run_id || ctx.run_id || "",
        }),
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.error) {
        const errMsg = d.error || d.detail || ("HTTP " + res.status);
        aiMsg.bubble.textContent = "Error: " + errMsg;
        aiMsg.meta.textContent = "HunterAI · error";
      } else {
        aiMsg.bubble.textContent = d.response || "Done";
        const cmdList = Array.isArray(d.executed)
          ? d.executed
          : (Array.isArray(d.commands) ? d.commands : []);
        const didExec = Boolean(
          (typeof d.executed === "boolean" && d.executed) ||
          cmdList.length > 0
        );
        const metaBits = ["HunterAI", d.provider || provider];
        if (d.model_used) metaBits.push(d.model_used);
        if (!allowExec) metaBits.push("exec disabled");
        else if (didExec) metaBits.push(`executed ${cmdList.length || ""} command(s)`.trim());
        aiMsg.meta.textContent = metaBits.join(" · ");

        if (d.terminal_output && d.terminal_output !== "(no commands executed)") {
          appendTerminal(d.terminal_output);
        } else if (cmdList.length > 0) {
          const formatted = cmdList.map((c) => `$ ${c.command || ""}\n${c.stdout || ""}${c.stderr || ""}`).join("\n");
          appendTerminal(formatted);
        }
      }
    } catch (err) {
      aiMsg.bubble.textContent = "Connection error: " + (err && err.message ? err.message : String(err));
      aiMsg.meta.textContent = "HunterAI · connection error";
    } finally {
      isBusy = false;
      scrollMsgs();
    }
    return false;
  }

  function appendUserMsg(text) {
    const box = document.getElementById("chat-messages");
    if (!box) return;
    const div = document.createElement("div");
    div.className = "chat-msg user";

    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";
    bubble.textContent = String(text ?? "");

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `You · ${new Date().toLocaleTimeString()}`;

    div.appendChild(bubble);
    div.appendChild(meta);
    box.appendChild(div);
    scrollMsgs();
  }

  function appendAIMsg(placeholder) {
    const box = document.getElementById("chat-messages");
    const div = document.createElement("div");
    div.className = "chat-msg ai";

    const bubble = document.createElement("div");
    bubble.className = "chat-bubble";
    bubble.textContent = String(placeholder ?? "");

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = "HunterAI · thinking...";

    div.appendChild(bubble);
    div.appendChild(meta);
    if (box) {
      box.appendChild(div);
      scrollMsgs();
    }
    return { wrap: div, bubble: bubble, meta: meta };
  }

  function appendTerminal(output) {
    const box = document.getElementById("term-output");
    if (!box) return;
    const lines = String(output ?? "").split("\n");
    for (const line of lines) {
      if (!line.trim()) continue;
      const div = document.createElement("div");
      div.className = "term-line ltr-isolate";
      if (line.startsWith("$ ")) {
        const promptSpan = document.createElement("span");
        promptSpan.className = "term-prompt";
        promptSpan.textContent = "hunterai> ";
        const cmdSpan = document.createElement("span");
        cmdSpan.className = "term-cmd";
        cmdSpan.textContent = line.slice(2);
        div.appendChild(promptSpan);
        div.appendChild(cmdSpan);
      } else if (line.startsWith("[ERR]") || line.startsWith("[!]")) {
        const errSpan = document.createElement("span");
        errSpan.className = "term-err";
        errSpan.textContent = line;
        div.appendChild(errSpan);
      } else {
        const outSpan = document.createElement("span");
        outSpan.className = "term-out";
        outSpan.textContent = line;
        div.appendChild(outSpan);
      }
      box.appendChild(div);
    }
    scrollTerminal();
  }

  function clearTerminal() {
    const box = document.getElementById("term-output");
    if (!box) return;
    box.textContent = "";
    const line = document.createElement("div");
    line.className = "term-line ltr-isolate";
    const promptSpan = document.createElement("span");
    promptSpan.className = "term-prompt";
    promptSpan.textContent = "hunterai> ";
    const outSpan = document.createElement("span");
    outSpan.className = "term-out";
    outSpan.textContent = "Terminal cleared.";
    line.appendChild(promptSpan);
    line.appendChild(outSpan);
    box.appendChild(line);
  }

  function scrollMsgs() {
    const box = document.getElementById("chat-messages");
    if (box) box.scrollTop = box.scrollHeight;
  }

  function scrollTerminal() {
    const box = document.getElementById("term-output");
    if (box) box.scrollTop = box.scrollHeight;
  }

  function init() {
    const core = window.HunterCore;
    if (core) {
      core.initTheme();
      if (typeof core.initI18n === "function") core.initI18n();
    }

    setupInput();

    const saveBtn = document.getElementById("save-settings-btn");
    if (saveBtn) saveBtn.addEventListener("click", saveSettings);

    const form = document.getElementById("chat-composer");
    if (form) form.addEventListener("submit", sendChat);

    const clearBtn = document.getElementById("clear-term-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearTerminal);

    const provSel = document.getElementById("provider-select");
    if (provSel) {
      provSel.addEventListener("change", function () {
        applyProviderDefaultModel(provSel.value);
      });
    }

    const execChk = document.getElementById("exec-chk");
    if (execChk) {
      execChk.addEventListener("change", function () { syncExecStatus(); });
      syncExecStatus();
    }

    const themeBtn = document.getElementById("cmdThemeToggle");
    if (themeBtn && core) {
      themeBtn.addEventListener("click", function () { core.toggleTheme(); });
    }

    const langBtn = document.getElementById("cmdLangToggle");
    if (langBtn && core) {
      const syncLangLabel = function () {
        langBtn.textContent = core.getLang() === "ar" ? "EN" : "AR";
      };
      langBtn.addEventListener("click", function () {
        core.setLang(core.getLang() === "ar" ? "en" : "ar");
        syncLangLabel();
      });
      window.addEventListener("hunter:langchange", syncLangLabel);
      syncLangLabel();
    }

    const backLink = document.getElementById("cmdWorkspaceLink");
    if (backLink && core) {
      const updateHref = function () {
        backLink.href = "/?theme=" + encodeURIComponent(core.getTheme()) + "&lang=" + encodeURIComponent(core.getLang());
      };
      updateHref();
      window.addEventListener("hunter:themechange", updateHref);
      window.addEventListener("hunter:langchange", updateHref);
    }

    loadSettings();
    if (core && typeof core.createVisibilityPoller === "function") {
      core.createVisibilityPoller(loadSettings, 15000, { immediate: false });
    }
  }

  window.saveSettings = saveSettings;
  window.sendChat = sendChat;
  window.clearTerminal = clearTerminal;

  document.addEventListener("DOMContentLoaded", init);
})();
