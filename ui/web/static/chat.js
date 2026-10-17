/* PentestAI — Claude-like chat client
   Talks to the existing /ws/chat WebSocket and the new /api/models/catalog.
   No client-side faking: assistant text is exactly what the backend returns;
   the "trace" panel renders the real progress events emitted by the engine. */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const STORE_KEY = "pentestai.chat.v1";

  // ── state ──────────────────────────────────────────────────────────────
  let state = { conversations: [], activeId: null };
  let ws = null;
  let wsReady = false;
  let pending = false;          // a request is in flight
  let pendingEl = null;         // assistant DOM node being filled
  let pendingConvId = null;
  let pendingText = "";         // streamed text accumulated so far

  // ── helpers ────────────────────────────────────────────────────────────
  const uid = () => Math.random().toString(36).slice(2, 10);
  const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

  function inline(t) {
    let s = esc(t);
    s = s.replace(/`([^`\n]+)`/g, '<code class="inline">$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    return s;
  }

  function md(src) {
    const lines = String(src ?? "").replace(/\r\n/g, "\n").split("\n");
    let html = "", inCode = false, buf = [], inList = false;
    const flushCode = () => { html += `<pre><code>${buf.join("\n")}</code></pre>`; buf = []; inCode = false; };
    const flushList = () => { if (inList) { html += "</ul>"; inList = false; } };

    for (const raw of lines) {
      if (/^```/.test(raw)) {
        if (inCode) flushCode(); else { flushList(); inCode = true; }
        continue;
      }
      if (inCode) { buf.push(esc(raw)); continue; }
      const li = raw.match(/^\s*[-*]\s+(.*)$/);
      if (li) { if (!inList) { html += "<ul>"; inList = true; } html += `<li>${inline(li[1])}</li>`; continue; }
      flushList();
      if (!raw.trim()) continue;
      const h = raw.match(/^#{1,6}\s+(.*)$/);
      if (h) { html += `<p><strong>${inline(h[1])}</strong></p>`; continue; }
      html += `<p>${inline(raw)}</p>`;
    }
    if (inCode) flushCode();
    flushList();
    return html || "<p></p>";
  }

  const now = () => Date.now();

  // ── persistence ────────────────────────────────────────────────────────
  function load() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) state = JSON.parse(raw);
    } catch (_) { /* ignore corrupt state */ }
    if (!Array.isArray(state.conversations)) state.conversations = [];
    if (!state.activeId || !find(state.activeId)) state.activeId = null;
  }
  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (_) {}
  }
  const find = (id) => state.conversations.find((c) => c.id === id) || null;
  function activeConv() { return find(state.activeId); }

  function newConversation() {
    const c = { id: uid(), title: "New chat", messages: [], createdAt: now() };
    state.conversations.unshift(c);
    state.activeId = c.id;
    save();
    renderConvs();
    renderThread();
    return c;
  }
  function ensureConversation() {
    return activeConv() || newConversation();
  }

  // ── rendering: conversations list ──────────────────────────────────────
  function renderConvs() {
    const box = $("convs");
    box.innerHTML = "";
    for (const c of state.conversations) {
      const el = document.createElement("div");
      el.className = "conv" + (c.id === state.activeId ? " active" : "");
      el.innerHTML = `<span class="t">${esc(c.title || "New chat")}</span><span class="x" title="Delete">✕</span>`;
      el.querySelector(".t").onclick = () => { state.activeId = c.id; save(); renderConvs(); renderThread(); };
      el.querySelector(".x").onclick = (e) => {
        e.stopPropagation();
        state.conversations = state.conversations.filter((x) => x.id !== c.id);
        if (state.activeId === c.id) state.activeId = state.conversations[0]?.id || null;
        save(); renderConvs(); renderThread();
      };
      box.appendChild(el);
    }
  }

  // ── rendering: thread ──────────────────────────────────────────────────
  const SUGGESTIONS = [
    "اشرحلي منهجية اختبار اختراق ويب خطوة بخطوة",
    "حلّل ممكن يكون فيه ثغرة في endpoint /api/v1/users/{id}",
    "اكتبلي سكربت Python لفحص أمان headers",
    "إزاي أثبّت SSRF بشكل قطعي؟",
  ];

  function renderThread() {
    const box = $("messages");
    const conv = activeConv();
    if (!conv || conv.messages.length === 0) {
      box.innerHTML = "";
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.innerHTML = `
        <div class="big">إزاي أساعدك <span class="m">النهارده؟</span></div>
        <div class="sub">مساعد أمني مدفوع بالأدلة — كل نتيجة مؤكَّدة لازم يكون معاها إثبات تنفيذ.</div>
        <div class="chips">${SUGGESTIONS.map((s) => `<button class="chip">${esc(s)}</button>`).join("")}</div>`;
      empty.querySelectorAll(".chip").forEach((b) => {
        b.onclick = () => { $("input").value = b.textContent; submit(); };
      });
      box.appendChild(empty);
      return;
    }
    box.innerHTML = "";
    const thread = document.createElement("div");
    thread.className = "thread";
    for (const m of conv.messages) thread.appendChild(messageNode(m));
    box.appendChild(thread);
    scrollDown();
  }

  function messageNode(m) {
    const wrap = document.createElement("div");
    wrap.className = "msg " + (m.role === "user" ? "user" : "assistant");
    wrap.innerHTML = `
      <div class="avatar">${m.role === "user" ? "🧑" : "✳"}</div>
      <div class="body">
        <div class="content"></div>
        ${m.role === "assistant" ? '<div class="meta"></div>' : ""}
      </div>`;
    const content = wrap.querySelector(".content");
    if (m.trace && m.trace.length) content.appendChild(traceNode(m.trace, !m.pending));
    const textEl = document.createElement("div");
    textEl.className = "text";
    if (m.pending && !m.content) {
      textEl.innerHTML = '<span class="typing"><span></span><span></span><span></span></span>';
    } else {
      textEl.innerHTML = m.role === "user" ? esc(m.content).replace(/\n/g, "<br>") : md(m.content);
    }
    content.appendChild(textEl);

    const meta = wrap.querySelector(".meta");
    if (meta) {
      if (m.meta && (m.meta.route || m.meta.model || m.meta.duration != null)) {
        const bits = [];
        if (m.meta.model) bits.push(esc(m.meta.model));
        if (m.meta.route) bits.push(esc(m.meta.route));
        if (m.meta.duration != null) bits.push(`${m.meta.duration}s`);
        meta.innerHTML = bits.join(" · ");
      }
      if (m.content && !m.pending) {
        const btn = document.createElement("button");
        btn.className = "copy-btn";
        btn.textContent = "Copy";
        btn.onclick = () => { navigator.clipboard?.writeText(m.content); btn.textContent = "Copied ✓";
          setTimeout(() => (btn.textContent = "Copy"), 1200); };
        meta.appendChild(btn);
      }
    }
    return wrap;
  }

  function traceNode(trace, done) {
    const el = document.createElement("div");
    el.className = "trace" + (done ? " done" : "");
    el.innerHTML = `
      <div class="trace-head"><span class="spin"></span><span>${done ? "خطوات التنفيذ" : "جاري التنفيذ…"}</span><span style="margin-left:auto">▾</span></div>
      <div class="trace-body"></div>`;
    const body = el.querySelector(".trace-body");
    trace.forEach((t) => { const d = document.createElement("div"); d.textContent = "› " + t; body.appendChild(d); });
    el.querySelector(".trace-head").onclick = () => el.classList.toggle("collapsed");
    return el;
  }

  function scrollDown() {
    const box = $("messages");
    box.scrollTop = box.scrollHeight;
  }

  // ── websocket ──────────────────────────────────────────────────────────
  function setConn(stateName, text) {
    const dot = $("connDot");
    dot.className = "dot " + stateName;
    $("connText").textContent = text;
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    try {
      ws = new WebSocket(`${proto}://${location.host}/ws/chat`);
    } catch (e) { setConn("off", "لا يمكن الاتصال"); return; }

    ws.onopen = () => { wsReady = true; setConn("on", "متصل — المحرّك جاهز"); };
    ws.onclose = () => { wsReady = false; setConn("off", "انقطع الاتصال — إعادة محاولة…"); setTimeout(connect, 2500); };
    ws.onerror = () => setConn("off", "خطأ في الاتصال");
    ws.onmessage = (ev) => {
      let d;
      try { d = JSON.parse(ev.data); } catch (_) { return; }
      handleEvent(d);
    };
  }

  function handleEvent(d) {
    if (!pending) return;
    const ev = d.event;
    if (ev === "chat_response") {
      finishAssistant(d.answer, { route: d.route, duration: d.duration, model: d.model_used });
      return;
    }
    if (ev === "error") {
      finishAssistant("⚠️ " + (d.message || "خطأ غير متوقّع"), null, true);
      return;
    }
    if (ev === "token" || ev === "chat_token") {
      // Real token delta from the backend — append and re-render progressively.
      // Cloud adapters emit {delta}; local Ollama routes emit {token}.
      const textEl = pendingEl && pendingEl.querySelector(".content .text");
      if (textEl) {
        pendingText += d.delta ?? d.token ?? "";
        textEl.innerHTML = md(pendingText);
        scrollDown();
      }
      return;
    }
    if (!pendingEl) return;
    const body = pendingEl.querySelector(".trace-body");
    if (!body) return;
    const push = (txt) => { const div = document.createElement("div"); div.textContent = "› " + txt; body.appendChild(div); scrollDown(); };
    if (ev === "chat_start") push(`start · model=${d.selected_model || "auto"}`);
    else if (ev === "task_classified") push(`classified: ${d.task_type || "?"} → ${(d.models || []).join(", ") || "—"}`);
    else if (ev === "step") push(`${d.model || "model"} · ${d.action || "working"}`);
    else if (ev === "step_done") push(`done · ${d.model || ""} (${d.chars || 0} chars)`);
    else if (ev === "route_done") push(`route=${d.route || ""}`);
    else if (ev === "chat_done") push(`finished in ${d.duration}s`);
  }

  function finishAssistant(text, meta, isError) {
    const conv = find(pendingConvId);
    if (!conv) { pending = false; return; }
    const last = [...conv.messages].reverse().find((m) => m.role === "assistant" && m.pending);
    if (last) {
      last.content = text;
      last.meta = meta || last.meta;
      last.pending = false;
    }
    pending = false;
    save();
    if (isError) setConn("off", "خطأ — تحقّق من الإعداد");
    renderConvs();
    renderThread();
  }

  // ── send ───────────────────────────────────────────────────────────────
  function submit() {
    const input = $("input");
    const text = input.value.trim();
    if (!text || pending) return;

    const conv = ensureConversation();
    conv.messages.push({ role: "user", content: text });
    if (conv.title === "New chat" || !conv.title) conv.title = text.slice(0, 42);
    const assistant = { role: "assistant", content: "", trace: [], pending: true, meta: null };
    conv.messages.push(assistant);
    save();

    input.value = "";
    input.style.height = "auto";
    pending = true;
    pendingConvId = conv.id;
    pendingText = "";
    renderConvs();
    renderThread();

    // locate the assistant node to stream real progress events into it
    const nodes = document.querySelectorAll("#messages .msg.assistant");
    pendingEl = nodes[nodes.length - 1] || null;

    if (!wsReady) {
      finishAssistant("⚠️ الاتصال بالمحرّك غير جاهز — جاري إعادة المحاولة…", null, true);
      return;
    }
    // Reflect the thinking trace immediately.
    const content = pendingEl?.querySelector(".content");
    if (content && !content.querySelector(".trace")) {
      content.insertBefore(traceNode([], false), content.firstChild);
      pendingEl.querySelector(".trace")?.querySelector(".trace-body")?.appendChild(
        Object.assign(document.createElement("div"), { textContent: "› queued" }));
    }

    ws.send(JSON.stringify({ message: text, model: $("modelSelect").value || "auto" }));
  }

  // ── model catalog ──────────────────────────────────────────────────────
  async function loadCatalog() {
    try {
      const r = await fetch("/api/models/catalog");
      const cat = await r.json();
      fillModels(cat);
    } catch (e) {
      $("modelHint").textContent = "تعذّر تحميل الكتالوج";
    }
  }

  function fillModels(cat) {
    const sel = $("modelSelect");
    const prev = sel.value;
    sel.innerHTML = '<option value="auto">Auto (smart router)</option>';

    const cloudLabels = {};
    (cat.cloud || []).forEach((c) => { cloudLabels[c.provider] = c.label; });

    const groups = {};
    (cat.choices || []).forEach((ch) => {
      const key = ch.kind === "local" ? "محلي · Ollama" : "سحابي · " + (cloudLabels[ch.provider] || ch.provider);
      (groups[key] = groups[key] || []).push(ch);
    });

    let firstCloudId = null, firstAnyId = null;
    for (const [label, items] of Object.entries(groups)) {
      const og = document.createElement("optgroup");
      og.label = label;
      for (const it of items) {
        const o = document.createElement("option");
        o.value = it.id;
        o.textContent = it.model;
        og.appendChild(o);
        if (!firstAnyId) firstAnyId = it.id;
        if (!firstCloudId && it.kind === "cloud") firstCloudId = it.id;
      }
      sel.appendChild(og);
    }

    // Cloud-first default (owner policy), then local, then auto.
    sel.value = prev && [...sel.options].some((o) => o.value === prev)
      ? prev : (firstCloudId || firstAnyId || "auto");

    $("policyTag").textContent = "policy: " + (cat.policy || "—");

    const nCloud = (cat.choices || []).filter((c) => c.kind === "cloud").length;
    const nLocal = (cat.choices || []).filter((c) => c.kind === "local").length;
    $("modelHint").textContent = cat.choices?.length
      ? `${nCloud} سحابي · ${nLocal} محلي`
      : "مفيش مزوّد متاح — ضيف مفتاح API في .env أو شغّل Ollama";
  }

  // ── wire up ────────────────────────────────────────────────────────────
  function init() {
    load();
    if (state.conversations.length === 0) newConversation();
    renderConvs();
    renderThread();

    $("composer").addEventListener("submit", (e) => { e.preventDefault(); submit(); });
    const input = $("input");
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    input.addEventListener("input", () => {
      input.style.height = "auto";
      input.style.height = Math.min(input.scrollHeight, 200) + "px";
    });

    $("newChat").onclick = () => { newConversation(); input.focus(); };
    $("menuBtn").onclick = () => $("sidebar").classList.toggle("collapsed");
    $("clearBtn").onclick = () => {
      const c = activeConv();
      if (c) { c.messages = []; c.title = "New chat"; save(); renderConvs(); renderThread(); }
    };

    loadCatalog();
    connect();
    input.focus();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
