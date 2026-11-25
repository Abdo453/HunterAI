/* HunterAI Command Center JS — Hardened DOM updates & visibility-aware polling */

(function () {
  "use strict";

  let isBusy = false;

  function notify(msg, tone) {
    if (window.HunterCore && typeof window.HunterCore.toast === "function") {
      window.HunterCore.toast(msg, tone || "info");
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
      const box = document.getElementById("provider-status");
      if (!box) return;
      box.textContent = "";

      const providers = d.providers || {};
      const entries = Object.entries(providers);
      for (const [k, v] of entries) {
        const chip = document.createElement("span");
        chip.className = "status-chip ltr-isolate " + (v ? "ok" : "miss");
        chip.textContent = `${k}: ${v ? "Ready" : "Missing"}`;
        box.appendChild(chip);
        box.appendChild(document.createTextNode(" "));
      }

      if (d.default_provider) {
        const sel = document.getElementById("provider-select");
        if (sel && [...sel.options].some((o) => o.value === d.default_provider)) {
          sel.value = d.default_provider;
        }
      }
      if (d.default_model) {
        const mEl = document.getElementById("model-input");
        if (mEl && !mEl.value) mEl.value = d.default_model;
      }
      const execChip = document.getElementById("exec-status");
      if (execChip) {
        execChip.style.display = d.allow_exec ? "inline-flex" : "none";
      }
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

    try {
      const res = await fetch("/api/settings/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: prov, api_key: key, model: model }),
      });
      const d = await res.json();
      if (d.ok) {
        if (status) {
          status.style.color = "var(--emerald)";
          status.textContent = "Saved to .env & active now";
        }
        const apiKeyEl = document.getElementById("api-key-input");
        if (apiKeyEl) apiKeyEl.value = "";
        notify("Settings saved to .env", "success");
        loadSettings();
      } else {
        if (status) {
          status.style.color = "var(--red)";
          status.textContent = d.error || "Save failed";
        }
        notify(d.error || "Save failed", "error");
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
          engagement_id: ctx.engagement_id || "",
          run_id: ctx.run_id || "",
        }),
      });
      const d = await res.json();
      if (d.error) {
        aiMsg.bubble.textContent = "Error: " + d.error;
        aiMsg.meta.textContent = "HunterAI · error";
      } else {
        aiMsg.bubble.textContent = d.response || "Done";
        aiMsg.meta.textContent = `HunterAI · ${d.provider || provider}${d.executed ? " · executed commands" : ""}`;
        if (d.terminal_output) {
          appendTerminal(d.terminal_output);
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
    }

    setupInput();

    const saveBtn = document.getElementById("save-settings-btn");
    if (saveBtn) saveBtn.addEventListener("click", saveSettings);

    const form = document.getElementById("chat-composer");
    if (form) form.addEventListener("submit", sendChat);

    const clearBtn = document.getElementById("clear-term-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearTerminal);

    const themeBtn = document.getElementById("cmdThemeToggle");
    if (themeBtn && core) {
      themeBtn.addEventListener("click", function () { core.toggleTheme(); });
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
