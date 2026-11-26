/* ==========================================================================
   HunterAI Control Center — Interactive Console Controller (hunterai>)
   Tab autocompletion, ArrowUp/ArrowDown history, /ws/terminal + REST fallback
   ========================================================================== */
(function (global) {
  "use strict";

  const DEFAULT_COMMANDS = [
    "help",
    "status",
    "scan --target ",
    "agent start ",
    "agent pause ",
    "agent stop ",
    "agent restart ",
    "scope list",
    "scope add ",
    "scope remove ",
    "scope lock",
    "scope unlock",
    "mcp status",
    "mcp retry",
    "court status",
    "clear",
    "emergency stop",
  ];

  const AGENT_IDS = ["brain", "browser", "burp", "code_intel"];

  const state = {
    commands: DEFAULT_COMMANDS.slice(),
    history: [],
    historyIndex: -1,
    draftInput: "",
    ws: null,
    onCommandResult: null,
    renderedCount: 0,
    initialized: false,
  };

  function getEls() {
    return {
      output: document.getElementById("terminal-output"),
      input: document.getElementById("terminal-input"),
      hint: document.getElementById("terminal-hint"),
      wsBadge: document.getElementById("terminal-ws-badge"),
      sendBtn: document.getElementById("btn-terminal-send"),
      clearBtn: document.getElementById("btn-terminal-clear"),
      helpBtn: document.getElementById("btn-terminal-help"),
    };
  }

  function classifyLine(text, ok) {
    const s = String(text || "");
    if (ok === false || /^\[(error|scope blocked)\]/i.test(s) || s.includes("[Error]")) {
      return "term-error";
    }
    if (s.startsWith("hunterai>")) return "term-cmd";
    if (/^\[emergency\]/i.test(s)) return "term-error";
    if (/^\[agent-/i.test(s)) return "term-agent";
    if (/^\[court\]/i.test(s)) return "term-court";
    if (/^\[(scope|mcp|agents|control)\]/i.test(s)) return "term-warn";
    return "term-system";
  }

  function appendLine(text, cls) {
    const { output } = getEls();
    if (!output) return;
    const lines = String(text ?? "").split(/\r?\n/);
    for (const line of lines) {
      if (!line && lines.length === 1) continue;
      const div = document.createElement("div");
      div.className = `term-line ${cls || classifyLine(line, true)}`;
      div.textContent = line;
      output.appendChild(div);
    }
    output.scrollTop = output.scrollHeight;
  }

  function renderFullBuffer(entries) {
    const { output } = getEls();
    if (!output || !Array.isArray(entries)) return;
    output.innerHTML = "";
    for (const entry of entries) {
      if (!entry || typeof entry !== "object") continue;
      if (entry.command) {
        appendLine(`hunterai> ${entry.command}`, "term-cmd");
      }
      if (entry.output) {
        const lines = String(entry.output).split(/\r?\n/);
        for (const line of lines) {
          appendLine(line, classifyLine(line, entry.ok));
        }
      }
    }
    state.renderedCount = entries.length;
  }

  function syncCommands(cmds) {
    if (!Array.isArray(cmds) || cmds.length === 0) return;
    const merged = new Set(DEFAULT_COMMANDS);
    for (const c of cmds) {
      if (typeof c === "string" && c.trim()) merged.add(c);
    }
    state.commands = Array.from(merged);
  }

  function syncHistory(hist) {
    if (!Array.isArray(hist)) return;
    const combined = [];
    const seen = new Set();
    for (const item of hist) {
      const val = String(item || "").trim();
      if (val && !seen.has(val)) {
        seen.add(val);
        combined.push(val);
      }
    }
    for (const item of state.history) {
      const val = String(item || "").trim();
      if (val && !seen.has(val)) {
        seen.add(val);
        combined.push(val);
      }
    }
    state.history = combined.slice(-200);
    state.historyIndex = state.history.length;
  }

  function longestCommonPrefix(items) {
    if (!items || items.length === 0) return "";
    let prefix = items[0];
    for (let i = 1; i < items.length; i++) {
      while (items[i].indexOf(prefix) !== 0) {
        prefix = prefix.slice(0, -1);
        if (!prefix) return "";
      }
    }
    return prefix;
  }

  function handleTabAutocomplete(input) {
    const raw = input.value;
    const lower = raw.toLowerCase();
    const { hint } = getEls();

    // Agent ID second-stage completion: e.g. "agent start b" -> "agent start brain"
    const agentMatch = raw.match(/^(agent\s+(?:start|pause|stop|restart)\s+)([a-z0-9_-]*)$/i);
    if (agentMatch) {
      const prefix = agentMatch[1];
      const partial = agentMatch[2].toLowerCase();
      const ids = AGENT_IDS.filter((id) => id.startsWith(partial));
      if (ids.length === 1) {
        input.value = `${prefix}${ids[0]}`;
        if (hint) hint.textContent = `Completed agent: ${ids[0]}`;
      } else if (ids.length > 1) {
        const lcp = longestCommonPrefix(ids);
        if (lcp.length > partial.length) {
          input.value = `${prefix}${lcp}`;
        }
        if (hint) hint.textContent = `Agents: ${ids.join("  |  ")}`;
      }
      return;
    }

    const matches = state.commands.filter((cmd) => cmd.toLowerCase().startsWith(lower));
    if (matches.length === 1) {
      input.value = matches[0];
      if (hint) hint.textContent = `Completed: ${matches[0]}`;
    } else if (matches.length > 1) {
      const lcp = longestCommonPrefix(matches);
      if (lcp.length > raw.length) {
        input.value = lcp;
      }
      if (hint) hint.textContent = `Matches (${matches.length}): ${matches.join(" | ")}`;
    } else if (hint) {
      hint.textContent = "No matching command. Type 'help' for available commands.";
    }
  }

  function handleHistoryNavigation(input, direction) {
    if (state.history.length === 0) return;

    if (direction === "up") {
      if (state.historyIndex >= state.history.length) {
        state.draftInput = input.value;
        state.historyIndex = state.history.length - 1;
      } else if (state.historyIndex > 0) {
        state.historyIndex -= 1;
      }
      input.value = state.history[state.historyIndex] || "";
    } else if (direction === "down") {
      if (state.historyIndex < state.history.length - 1) {
        state.historyIndex += 1;
        input.value = state.history[state.historyIndex] || "";
      } else {
        state.historyIndex = state.history.length;
        input.value = state.draftInput || "";
      }
    }
    requestAnimationFrame(() => {
      input.setSelectionRange(input.value.length, input.value.length);
    });
  }

  function handlePayload(data) {
    if (!data || typeof data !== "object") return;

    if (data.type === "pong") return;

    const payloadState = data.state && typeof data.state === "object" ? data.state : data;
    syncCommands(payloadState.commands);
    syncHistory(payloadState.history);

    if (data.cleared) {
      clearLocal();
      return;
    }

    if (data.type === "state" || (!("command" in data) && Array.isArray(payloadState.output))) {
      renderFullBuffer(payloadState.output);
      return;
    }

    if (Array.isArray(data.lines) && data.lines.length > 0) {
      for (const line of data.lines) {
        appendLine(line, classifyLine(line, data.ok));
      }
    } else if (typeof data.output === "string" && data.output.trim()) {
      appendLine(data.output, classifyLine(data.output, data.ok));
    } else if (Array.isArray(payloadState.output)) {
      renderFullBuffer(payloadState.output);
    }

    if (typeof state.onCommandResult === "function" && data.command) {
      state.onCommandResult(data);
    }
  }

  function clearLocal() {
    const { output } = getEls();
    if (output) {
      output.innerHTML = "";
    }
    state.renderedCount = 0;
  }

  async function execute(rawCommand) {
    const cmd = String(rawCommand || "").trim();
    if (!cmd) return;

    if (!state.history.length || state.history[state.history.length - 1] !== cmd) {
      state.history.push(cmd);
      if (state.history.length > 200) state.history.shift();
    }
    state.historyIndex = state.history.length;
    state.draftInput = "";

    if (cmd.toLowerCase() === "clear") {
      clearLocal();
    } else {
      appendLine(`hunterai> ${cmd}`, "term-cmd");
    }

    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      try {
        state.ws.send(JSON.stringify({ command: cmd }));
        return;
      } catch (err) {
        // Fallback to HTTP REST below
      }
    }

    try {
      const resp = await fetch("/api/terminal/command", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd }),
      });
      const data = await resp.json();
      handlePayload(data);
    } catch (err) {
      appendLine(`[Error] Failed to execute command: ${err.message}`, "term-error");
    }
  }

  function setSocket(ws) {
    state.ws = ws;
  }

  function setSocketStatus(statusText) {
    const { wsBadge } = getEls();
    if (wsBadge) {
      wsBadge.textContent = `Stream: ${statusText}`;
    }
  }

  function setOnCommandResult(fn) {
    state.onCommandResult = fn;
  }

  function init() {
    if (state.initialized) return;
    state.initialized = true;

    const { input, sendBtn, clearBtn, helpBtn } = getEls();

    if (input) {
      input.addEventListener("keydown", (ev) => {
        if (ev.key === "Tab") {
          ev.preventDefault();
          handleTabAutocomplete(input);
        } else if (ev.key === "ArrowUp") {
          ev.preventDefault();
          handleHistoryNavigation(input, "up");
        } else if (ev.key === "ArrowDown") {
          ev.preventDefault();
          handleHistoryNavigation(input, "down");
        } else if (ev.key === "Enter") {
          ev.preventDefault();
          const val = input.value;
          input.value = "";
          execute(val);
        }
      });
    }

    if (sendBtn && input) {
      sendBtn.addEventListener("click", () => {
        const val = input.value;
        input.value = "";
        execute(val);
        input.focus();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", () => execute("clear"));
    }

    if (helpBtn) {
      helpBtn.addEventListener("click", () => execute("help"));
    }
  }

  global.HunterTerminal = {
    init,
    execute,
    clear: () => execute("clear"),
    appendLine,
    handlePayload,
    setSocket,
    setSocketStatus,
    setOnCommandResult,
  };
})(window);
