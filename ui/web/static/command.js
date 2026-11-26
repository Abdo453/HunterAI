'use strict';

/* ════════════════════════════════════════════════════════════════════
   PentestAI Command Center — frontend controller
   Panels: Left = Settings & Target, Middle = Chat, Right = Terminal
   ════════════════════════════════════════════════════════════════════ */

let terminalLines = [];

document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  setupInput();
  // Keep provider status fresh in case keys are saved elsewhere
  setInterval(loadSettings, 15000);
});

function setupInput() {
  const ta = document.getElementById('chat-input');
  ta.addEventListener('input', () => {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 140) + 'px';
  });
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChat(e);
    }
  });
}

/* ── Settings / API Management ─────────────────────────────────────── */

async function loadSettings() {
  try {
    const res = await fetch('/api/settings');
    const d = await res.json();
    const box = document.getElementById('provider-status');
    if (!box) return;
    box.innerHTML = '';
    for (const prov of (d.providers || [])) {
      const k = (d.keys || {})[prov] || {};
      const chip = document.createElement('div');
      chip.className = `status-chip ${k.configured ? 'ok' : 'bad'}`;
      chip.textContent = `${prov.toUpperCase()}: ${k.configured ? 'configured (' + k.key_masked + ')' : 'not set'}`;
      box.appendChild(chip);
    }
    // Prefill model input with the provider default when empty
    const sel = document.getElementById('provider-select').value;
    const def = (d.default_models || {})[sel];
    const mi = document.getElementById('model-input');
    if (def && !mi.value) mi.value = def;
  } catch (err) {
    console.error('loadSettings error', err);
  }
}

async function saveSettings() {
  const prov = document.getElementById('provider-select').value;
  const key = document.getElementById('api-key-input').value.trim();
  const model = document.getElementById('model-input').value.trim();
  const statusEl = document.getElementById('save-status');
  statusEl.textContent = 'Saving to .env…';
  statusEl.style.color = 'var(--amber)';
  try {
    const res = await fetch('/api/settings/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [prov]: key, model }),
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'save failed');
    statusEl.textContent = d.note || 'Saved to .env — live reload complete.';
    statusEl.style.color = 'var(--emerald)';
    document.getElementById('api-key-input').value = '';
    loadSettings();
  } catch (err) {
    statusEl.textContent = 'Save failed: ' + err;
    statusEl.style.color = 'var(--rose)';
  }
}

/* ── Chat ──────────────────────────────────────────────────────────── */

async function sendChat(e) {
  if (e) e.preventDefault();
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return false;
  input.value = '';
  input.style.height = 'auto';

  const provider = document.getElementById('provider-select').value;
  const model = document.getElementById('model-input').value.trim();

  appendUserMsg(text);
  scrollMsgs();

  const aiDiv = appendAIMsg('');

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, provider, model }),
    });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'chat failed');

    const aiText = d.response || '(no response)';
    const bubble = aiDiv.querySelector('.chat-bubble');
    const meta = aiDiv.querySelector('.meta');
    bubble.textContent = aiText;
    meta.textContent = `PentestAI · ${d.provider} · ${d.model_used}`;

    // Render terminal output from executed commands
    if (d.terminal_output && d.terminal_output !== '(no commands executed)') {
      appendTerminal(d.terminal_output);
    }
  } catch (err) {
    const bubble = aiDiv.querySelector('.chat-bubble');
    bubble.textContent = 'Error: ' + err;
    bubble.style.color = 'var(--rose)';
  }
  scrollMsgs();
  scrollTerminal();
  return false;
}

function appendUserMsg(text) {
  const box = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = 'chat-msg user';
  div.innerHTML = `<div class="chat-bubble">${escapeHtml(text)}</div><div class="meta">You · ${new Date().toLocaleTimeString()}</div>`;
  box.appendChild(div);
  return div;
}

function appendAIMsg(placeholder) {
  const box = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = 'chat-msg ai';
  div.innerHTML = `<div class="chat-bubble">${placeholder}</div><div class="meta">PentestAI · thinking…</div>`;
  box.appendChild(div);
  return div;
}

/* ── Terminal ──────────────────────────────────────────────────────── */

function appendTerminal(output) {
  const box = document.getElementById('term-output');
  const lines = String(output).split(/\r?\n/).filter((l) => l.length > 0);
  for (const line of lines) {
    const div = document.createElement('div');
    div.className = 'term-line';
    if (line.startsWith('$ ')) {
      div.innerHTML = `<span class="term-prompt">pentestai></span> <span class="term-cmd">${escapeHtml(line.slice(2))}</span>`;
    } else if (/timed out|error|fail|traceback|exception/i.test(line)) {
      div.innerHTML = `<span class="term-err">${escapeHtml(line)}</span>`;
    } else {
      div.innerHTML = `<span class="term-out">${escapeHtml(line)}</span>`;
    }
    box.appendChild(div);
    terminalLines.push(div);
  }
  // Bound the DOM so long sessions stay snappy
  if (terminalLines.length > 400) {
    terminalLines.splice(0, terminalLines.length - 400).forEach((d) => d.remove());
  }
}

function clearTerminal() {
  const box = document.getElementById('term-output');
  box.innerHTML = '<div class="term-line"><span class="term-prompt">pentestai></span> <span class="term-out">Terminal cleared.</span></div>';
  terminalLines = [];
}

function scrollMsgs() {
  const box = document.getElementById('chat-messages');
  box.scrollTop = box.scrollHeight;
}

function scrollTerminal() {
  const box = document.getElementById('term-output');
  box.scrollTop = box.scrollHeight;
}

function escapeHtml(s) {
  return String(s)
    .replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
