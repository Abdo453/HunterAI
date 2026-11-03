'use strict';

let currentPillar = 'omni';
let activeEngagementId = null;
let omniPollTimer = null;
let allArsenalTools = [];
let currentCategory = 'all';
let modalActiveTool = null;

// ── Document Ready ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadArsenalTools();
  setInterval(updateGPUStatus, 3500);
});

// ── Navigation Controller (5 Pillars) ─────────────────────────────────────────
function switchPillar(pillar, btn) {
  currentPillar = pillar;
  document.querySelectorAll('.pillar-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.pillar-viewport').forEach(v => v.classList.remove('active'));

  if (btn) btn.classList.add('active');
  const view = document.getElementById(`pillar-${pillar}`);
  if (view) view.classList.add('active');

  if (pillar === 'arsenal' && allArsenalTools.length === 0) {
    loadArsenalTools();
  }
}

// ── Hardware & Telemetry Status ───────────────────────────────────────────────
async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    renderLocalModels(data.local_models || []);
    renderApiKeys(data.api_keys || {});
  } catch (err) {
    console.error('Status fetch error:', err);
  }
}

function renderLocalModels(models) {
  const el = document.getElementById('models-list');
  if (!el) return;
  const defs = [
    { k: 'whiterabbitneo', l: 'WhiteRabbitNeo (Sec LLM)' },
    { k: 'qwen2.5-coder', l: 'Qwen2.5-Coder:14B' },
    { k: 'xploiter', l: 'xploiter/pentester' },
  ];
  el.innerHTML = defs.map(m => {
    const on = models.some(x => x.toLowerCase().includes(m.k));
    return `
      <div class="model-pill">
        <span class="dot-status ${on ? 'online' : ''}"></span>
        <span style="color:${on ? '#fff' : '#666'}">${m.l}</span>
      </div>`;
  }).join('');
}

function renderApiKeys(keys) {
  const el = document.getElementById('api-list');
  if (!el) return;
  el.innerHTML = Object.entries(keys).map(([k, v]) => `
    <div class="model-pill">
      <span class="dot-status ${v ? 'online' : ''}"></span>
      <span style="color:${v ? '#fff' : '#666'}">${k}</span>
    </div>
  `).join('');
}

function updateGPUStatus() {
  fetch('/api/status').then(r => r.json()).then(d => {
    const freeEl = document.getElementById('gpu-state');
    const modelEl = document.getElementById('gpu-model');
    if (!freeEl || !modelEl) return;
    const loaded = d.loaded_models || [];
    if (loaded.length > 0) {
      freeEl.textContent = 'ACTIVE';
      freeEl.className = 'gpu-metric-val';
      freeEl.style.color = 'var(--cyan)';
      modelEl.textContent = loaded[0];
    } else {
      freeEl.textContent = 'FREE (جاهز)';
      freeEl.className = 'gpu-metric-val free';
      modelEl.textContent = '—';
    }
  }).catch(() => {});
}

// ── PILLAR 1: OmniHunter Autonomous Mission Controller ────────────────────────
async function launchOmniMission() {
  const target = document.getElementById('omni-target-input').value.trim();
  const scopeStr = document.getElementById('omni-scope-input').value.trim();
  const authChecked = document.getElementById('omni-auth-chk').checked;
  const oobChecked = document.getElementById('omni-oob-chk').checked;
  const fallbackChecked = document.getElementById('omni-fallback-chk').checked;

  if (!target) {
    alert('يرجى إدخال نطاق الهدف!');
    return;
  }

  const pill = document.getElementById('mission-status-pill');
  pill.textContent = 'جاري إطلاق المهمة...';
  pill.className = 'status-badge badge-blue';

  try {
    const res = await fetch('/api/omni/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        scope: scopeStr,
        authorized: authChecked,
        enable_oob: oobChecked,
        force_fallback: fallbackChecked,
      })
    });
    const data = await res.json();
    if (data.engagement_id) {
      activeEngagementId = data.engagement_id;
      pill.textContent = `نشط: ${activeEngagementId}`;
      pill.className = 'status-badge badge-green';
      if (omniPollTimer) clearInterval(omniPollTimer);
      omniPollTimer = setInterval(() => pollOmniMission(activeEngagementId), 2500);
    }
  } catch (err) {
    pill.textContent = 'فشل الإطلاق';
    alert('خطأ في إطلاق المهمة: ' + err);
  }
}

async function pollOmniMission(engId) {
  try {
    const res = await fetch(`/api/omni/status/${engId}`);
    const data = await res.json();

    // Update active phase stepper
    const curPhase = data.current_phase || 'INIT';
    document.getElementById('active-phase-name').textContent = `Phase: ${curPhase}`;
    const steps = ['RECON', 'NETWORK', 'WEB', 'API', 'JAVASCRIPT', 'VERIFICATION', 'ADJUDICATION', 'REPORT'];
    const curIdx = steps.indexOf(curPhase);
    steps.forEach((s, i) => {
      const stepEl = document.getElementById(`step-${s}`);
      if (!stepEl) return;
      stepEl.className = 'ooda-step';
      if (i < curIdx) stepEl.classList.add('done');
      else if (i === curIdx) stepEl.classList.add('active');
    });

    // Update metrics
    const cov = data.coverage_pct || 0.0;
    document.getElementById('metric-coverage').textContent = `${cov.toFixed(1)}%`;
    document.getElementById('metric-coverage-bar').style.width = `${Math.min(100, cov)}%`;
    document.getElementById('metric-findings').textContent = data.confirmed_findings_count || 0;
    document.getElementById('metric-elapsed').textContent = `${data.elapsed_secs || 0}s`;

    // Render findings docket
    const findings = data.confirmed_findings || [];
    const tbody = document.getElementById('omni-findings-tbody');
    if (findings.length > 0) {
      tbody.innerHTML = findings.map((f, i) => `
        <tr>
          <td style="font-family:var(--font-mono);font-weight:bold;color:var(--cyan)">#FIND-${i+1}</td>
          <td><span class="risk-tag risk-critical">${f.vuln_class || 'Vulnerability'}</span></td>
          <td style="font-family:var(--font-mono);font-size:0.85em;">${f.target || 'target'}</td>
          <td><span class="status-badge badge-green">${f.verdict || 'CONFIRMED'}</span></td>
          <td><strong>${((f.confidence || 0.95) * 100).toFixed(0)}%</strong></td>
          <td>
            <button class="cyber-btn" style="padding:4px 10px;font-size:0.75em;" onclick="alert('حزمة PoC محفوظة في: ' + '${f.poc_bundle_dir || 'findings/'}')">
              📦 حزمة PoC
            </button>
          </td>
        </tr>
      `).join('');
    }

    if (data.status === 'COMPLETED' || data.status === 'FAILED') {
      clearInterval(omniPollTimer);
      const pill = document.getElementById('mission-status-pill');
      pill.textContent = data.status === 'COMPLETED' ? 'اكتملت المهمة ✅' : 'انتهت المهمة ⚠️';
    }
  } catch (err) {
    console.error('Polling error:', err);
  }
}

// ── PILLAR 2: Cognitive Reasoning Controller ──────────────────────────────────
async function runCognitiveDeliberation() {
  const target = document.getElementById('cog-target-input').value.trim();
  const obj = document.getElementById('cog-obj-input').value.trim();
  const box = document.getElementById('inner-monologue-box');

  box.textContent = '[*] جاري استدعاء محرك المداولة المعرفية (Claude Adaptive + DeepSeek-R1) وتحليل الفرضيات...';

  try {
    const res = await fetch('/api/cognitive/deliberate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target, objective: obj, stakes: 'high' })
    });
    const data = await res.json();

    // Render hypotheses cards
    const hyps = data.hypotheses || [];
    if (hyps.length > 0) {
      document.getElementById('h1-text').textContent = hyps[0].statement || '';
      document.getElementById('h1-falsify').textContent = hyps[0].refutation_criteria || '';
      document.getElementById('h1-conf').textContent = `Confidence: ${((hyps[0].confidence || 0.6) * 100).toFixed(0)}%`;
    }
    if (hyps.length > 1) {
      document.getElementById('h2-text').textContent = hyps[1].statement || '';
      document.getElementById('h2-falsify').textContent = hyps[1].refutation_criteria || '';
      document.getElementById('h2-conf').textContent = `Confidence: ${((hyps[1].confidence || 0.4) * 100).toFixed(0)}%`;
    }

    // Render trace in terminal
    box.textContent = data.formatted_trace || data.inner_monologue || 'Deliberation complete.';
  } catch (err) {
    box.textContent = 'خطأ في استدعاء محرك التفكير: ' + err;
  }
}

// ── PILLAR 3: Universal Kali Arsenal Controller ───────────────────────────────
async function loadArsenalTools() {
  try {
    const res = await fetch('/api/arsenal/tools');
    const data = await res.json();
    allArsenalTools = data.tools || [];

    const badge = document.getElementById('arsenal-count-badge');
    if (badge) badge.textContent = `${data.total} أداة (${data.installed} مثبتة)`;
    const sumBadge = document.getElementById('arsenal-summary-badge');
    if (sumBadge) sumBadge.textContent = `Arsenal: ${data.total} Tools (${data.installed} Local)`;

    renderArsenalGrid();
  } catch (err) {
    console.error('Arsenal load error:', err);
  }
}

function selectArsenalCategory(cat, btn) {
  currentCategory = cat;
  document.querySelectorAll('.cat-pill-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderArsenalGrid();
}

function filterArsenalTools() {
  renderArsenalGrid();
}

function renderArsenalGrid() {
  const container = document.getElementById('arsenal-tools-container');
  if (!container) return;

  const q = (document.getElementById('arsenal-search-box')?.value || '').toLowerCase().trim();
  const filtered = allArsenalTools.filter(t => {
    const matchCat = currentCategory === 'all' || t.category.toLowerCase() === currentCategory.toLowerCase();
    const matchQ = !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q) || t.package.toLowerCase().includes(q);
    return matchCat && matchQ;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:30px;color:var(--text-dim);">لا توجد أدوات مطابقة للبحث أو الفئة المحددة.</div>';
    return;
  }

  container.innerHTML = filtered.map(t => {
    const riskCls = `risk-${t.risk_level.toLowerCase()}`;
    const instCls = t.installed ? 'installed-yes' : 'installed-no';
    const instText = t.installed ? '● مثبت' : '○ غير مثبت (apt)';
    return `
      <div class="tool-tile">
        <div>
          <div class="tool-tile-top">
            <span class="tool-tile-name">${t.name}</span>
            <span class="risk-tag ${riskCls}">${t.risk_level}</span>
          </div>
          <div style="font-size:0.72em;color:var(--cyan);margin:3px 0 6px 0;font-family:var(--font-mono);">${t.category}</div>
          <div class="tool-tile-desc">${t.description}</div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;border-top:1px solid var(--border);padding-top:8px;">
          <span class="install-badge ${instCls}">${instText}</span>
          <button class="cyber-btn" style="padding:4px 10px;font-size:0.75em;" onclick="inspectTool('${t.name}')">
            <span>فحص وتشغيل</span> <span>🔍</span>
          </button>
        </div>
      </div>
    `;
  }).join('');
}

async function inspectTool(toolName) {
  modalActiveTool = toolName;
  const modal = document.getElementById('tool-modal');
  modal.style.display = 'flex';

  document.getElementById('modal-tool-title').textContent = `Agent Persona: ${toolName}`;
  document.getElementById('modal-sys-prompt').textContent = 'Loading persona...';
  document.getElementById('modal-mcp-schema').textContent = 'Loading schema...';
  document.getElementById('modal-exec-result').style.display = 'none';

  try {
    const res = await fetch(`/api/arsenal/tool/${toolName}`);
    const data = await res.json();
    document.getElementById('modal-sys-prompt').textContent = data.system_prompt || '';
    document.getElementById('modal-mcp-schema').textContent = JSON.stringify(data.mcp_schema || {}, null, 2);
  } catch (err) {
    document.getElementById('modal-sys-prompt').textContent = 'خطأ في جلب بيانات الأداة: ' + err;
  }
}

function closeToolModal(e) {
  if (e && e.target !== e.currentTarget && e.currentTarget.id !== 'tool-modal') return;
  document.getElementById('tool-modal').style.display = 'none';
}

async function executeModalTool() {
  if (!modalActiveTool) return;
  const target = document.getElementById('modal-exec-target').value.trim() || 'http://example.com';
  const outBox = document.getElementById('modal-exec-result');
  outBox.style.display = 'block';
  outBox.textContent = `[*] جاري تشغيل الأداة عبر DynamicToolAgent (${modalActiveTool} -> ${target})...`;

  try {
    const res = await fetch('/api/arsenal/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: modalActiveTool, target: target, force_fallback: true, thinking: true })
    });
    const data = await res.json();
    outBox.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    outBox.textContent = 'خطأ في التنفيذ: ' + err;
  }
}

// ── PILLAR 4: Chat Shell Controller ───────────────────────────────────────────
async function sendChatMessage() {
  const input = document.getElementById('chat-user-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';

  const box = document.getElementById('chat-messages-box');
  box.innerHTML += `
    <div style="background:rgba(255,255,255,0.05);border:1px solid var(--border);padding:10px 14px;border-radius:var(--radius-md);align-self:flex-end;max-width:85%;">
      <strong style="color:#fff;">أنت:</strong>
      <p style="margin-top:4px;font-size:0.88em;">${text}</p>
    </div>
  `;
  box.scrollTop = box.scrollHeight;

  // Placeholder AI response for instant interactivity
  setTimeout(() => {
    box.innerHTML += `
      <div style="background:rgba(0,229,255,0.08);border:1px solid rgba(0,229,255,0.2);padding:12px 16px;border-radius:var(--radius-md);max-width:85%;">
        <strong style="color:var(--cyan)">HunterAI Copilot:</strong>
        <p style="margin-top:4px;font-size:0.88em;">تم استلام طلبك: "${text}". يمكنك استخدام أمر <code>pentest think</code> للتفكير الاستدلالي أو تشغيل الفحص الذاتي عبر تبويب OmniHunter.</p>
      </div>
    `;
    box.scrollTop = box.scrollHeight;
  }, 400);
}

// ── PILLAR 5: Evidence Refresh ────────────────────────────────────────────────
function refreshLedgerView() {
  alert('سجل الأدلة متزامن ومحمي بواسطة Hash-Chained Audit Ledger.');
}
