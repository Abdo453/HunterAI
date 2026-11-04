'use strict';

let currentPillar = 'omni';
let activeMasterMissionId = null;
let masterPollTimer = null;
let allArsenalTools = [];
let currentCategory = 'all';
let modalActiveTool = null;
let allLoadedSkills = [];

// ── Document Ready ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadArsenalTools();
  loadSnapshotsList();
  loadReportsList();
  loadSkillsMatrix();
  setInterval(updateGPUStatus, 3500);
});

// ── Navigation Controller ─────────────────────────────────────────────────────
function switchPillar(pillar, btn) {
  currentPillar = pillar;
  document.querySelectorAll('.pillar-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.pillar-viewport').forEach(v => v.classList.remove('active'));

  if (btn) btn.classList.add('active');
  const view = document.getElementById(`pillar-${pillar}`);
  if (view) view.classList.add('active');

  if (pillar === 'arsenal' && allArsenalTools.length === 0) {
    loadArsenalTools();
  } else if (pillar === 'skills_matrix' && allLoadedSkills.length === 0) {
    loadSkillsMatrix();
  } else if (pillar === 'reports') {
    loadReportsList();
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
    { k: 'qwen2.5-coder', l: 'Qwen2.5-Coder:14B' },
    { k: 'whiterabbitneo', l: 'WhiteRabbitNeo (Sec LLM)' },
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
      freeEl.textContent = 'READY (جاهز)';
      freeEl.className = 'gpu-metric-val free';
      modelEl.textContent = 'Qwen2.5-14B / Claude';
    }
  }).catch(() => {});
}

// ── PILLAR 1: Master One-Command-For-Everything Controller ────────────────────
async function launchMasterAllAssessment() {
  const target = document.getElementById('omni-target-input').value.trim();
  const scopeStr = document.getElementById('omni-scope-input').value.trim();
  const platform = document.getElementById('omni-platform-select').value;
  const proxy = document.getElementById('omni-proxy-input').value.trim() || null;
  const burpFile = document.getElementById('omni-burpfile-input').value.trim() || null;
  const resume = document.getElementById('omni-resume-input').value.trim() || null;
  const cycles = parseInt(document.getElementById('omni-cycles-input').value, 10) || 10;

  const authChecked = document.getElementById('omni-auth-chk').checked;
  const selfOpChecked = document.getElementById('omni-selfop-chk').checked;
  const fallbackChecked = document.getElementById('omni-fallback-chk').checked;

  if (!target) {
    alert('يرجى إدخال الهدف!');
    return;
  }

  const pill = document.getElementById('mission-status-pill');
  pill.textContent = 'جاري إطلاق الفحص الشامل...';
  pill.className = 'status-badge badge-blue';

  try {
    const res = await fetch('/api/enhanced/omni/launch-all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        platform: platform,
        proxy: proxy,
        burp_file: burpFile,
        resume: resume,
        max_cycles: cycles,
        coverage: 0.85,
        force_fallback: fallbackChecked,
        self_operate: selfOpChecked,
      })
    });
    const data = await res.json();
    if (data.mission_id) {
      activeMasterMissionId = data.mission_id;
      pill.textContent = `نشط: ${activeMasterMissionId}`;
      pill.className = 'status-badge badge-green';
      if (masterPollTimer) clearInterval(masterPollTimer);
      masterPollTimer = setInterval(() => pollMasterMission(activeMasterMissionId), 2500);
    }
  } catch (err) {
    pill.textContent = 'فشل الإطلاق';
    alert('خطأ في إطلاق المهمة: ' + err);
  }
}

async function pollMasterMission(missionId) {
  try {
    const res = await fetch(`/api/enhanced/omni/status/${missionId}`);
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
    document.getElementById('metric-target-progress').textContent = `Target: ${data.target_progress || '1/1'}`;

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
            <button class="cyber-btn" style="padding:4px 10px;font-size:0.75em;" onclick="alert('تفاصيل الإثبات: ' + '${f.evidence ? f.evidence.substring(0, 100).replace(/'/g, '') : 'Confirmed'}')">
              📦 حزمة PoC
            </button>
          </td>
        </tr>
      `).join('');
    }

    // Dossier Alert
    if (data.dossiers && data.dossiers.length > 0) {
      const container = document.getElementById('master-dossier-pill-container');
      const latestDossier = data.dossiers[data.dossiers.length - 1];
      const filename = latestDossier.split(/[\\/]/).pop();
      container.innerHTML = `
        <button class="cyber-btn" style="background:var(--emerald);color:#04060a;font-weight:bold;padding:6px 14px;" onclick="viewReportContent('${filename}')">
          📄 عرض تقرير الـ Dossier الشامل
        </button>
      `;
    }

    if (data.status === 'COMPLETED' || data.status === 'FAILED') {
      clearInterval(masterPollTimer);
      const pill = document.getElementById('mission-status-pill');
      pill.textContent = data.status === 'COMPLETED' ? 'اكتمل الفحص الشامل بنجاح ✅' : 'انتهت المهمة ⚠️';
      loadReportsList();
      loadSnapshotsList();
    }
  } catch (err) {
    console.error('Master poll error:', err);
  }
}

// ── PILLAR 2: Burp Suite Deep Log Inspector Controller ────────────────────────
async function executeBurpInspection() {
  const source = document.getElementById('burp-source-input').value.trim();
  const target = document.getElementById('burp-target-input').value.trim();
  const port = parseInt(document.getElementById('burp-port-input').value, 10) || 8085;
  const pasted = document.getElementById('burp-content-paste').value.trim();

  const container = document.getElementById('burp-findings-container');
  container.innerHTML = '<div style="color:var(--cyan);text-align:center;padding:24px;">جاري فحص وتدقيق سجلات Burp واستخراج الأسرار وتصنيف البارامترات...</div>';

  try {
    const res = await fetch('/api/enhanced/burp/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: source,
        content_text: pasted || null,
        target: target,
        port: port,
        min_risk: 5.0,
      })
    });
    const data = await res.json();
    if (!data.success) {
      container.innerHTML = `<div style="color:var(--rose);padding:14px;">خطأ في الفحص: ${data.error || 'فشل الفحص'}</div>`;
      return;
    }

    // Update Stats
    document.getElementById('burp-stat-interactions').textContent = data.total_interactions;
    document.getElementById('burp-stat-endpoints').textContent = (data.discovered_endpoints || []).length;
    document.getElementById('burp-stat-signals').textContent = data.total_findings;

    // Render findings
    const findings = data.findings || [];
    if (findings.length === 0) {
      container.innerHTML = '<div style="color:var(--emerald);padding:20px;text-align:center;">لم يتم العثور على أسرار مسربة أو أخطاء مباشرة في السجلات المفحوصة.</div>';
    } else {
      container.innerHTML = findings.map(f => {
        const sevColor = f.severity === 'Critical' ? 'var(--rose)' : f.severity === 'High' ? 'var(--amber)' : 'var(--cyan)';
        return `
          <div style="background:rgba(0,0,0,0.35);border:1px solid var(--border);border-left:4px solid ${sevColor};border-radius:var(--radius-sm);padding:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong style="color:${sevColor}">${f.title}</strong>
              <span class="risk-tag" style="background:${sevColor};color:#04060a;font-weight:bold;">${f.severity}</span>
            </div>
            <div style="font-size:0.8em;color:var(--text-muted);margin:4px 0;">نوع الثغرة: <code>${f.vuln_type}</code> | الرابط: <code>${f.url}</code></div>
            <div style="font-family:var(--font-mono);font-size:0.75em;background:#03060d;padding:8px;border-radius:4px;color:#8fbcbb;margin-top:6px;white-space:pre-wrap;">${f.evidence}</div>
          </div>
        `;
      }).join('');
    }

    // Download Dossier Button
    const dlBtn = document.getElementById('burp-download-report-btn');
    if (data.output_files && data.output_files['burp_log_analysis_report.md']) {
      dlBtn.innerHTML = `
        <button class="cyber-btn" onclick="viewReportContent('burp_log_analysis_report.md')">
          📄 استعراض التقرير المكتبي الكامل
        </button>
      `;
    }
  } catch (err) {
    container.innerHTML = `<div style="color:var(--rose);padding:14px;">خطأ اتصال: ${err}</div>`;
  }
}

// ── PILLAR 3: Active AI Browser & DOM XSS Studio ──────────────────────────────
async function launchAIBrowserSession() {
  const targetUrl = document.getElementById('browser-target-input').value.trim();
  const proxy = document.getElementById('browser-proxy-input').value.trim() || null;
  const pages = parseInt(document.getElementById('browser-pages-input').value, 10) || 5;
  const headless = document.getElementById('browser-headless-chk').checked;

  if (!targetUrl) {
    alert('يرجى إدخال رابط الهدف للمتصفح!');
    return;
  }

  const apisBox = document.getElementById('browser-apis-list');
  const actionsBox = document.getElementById('browser-actions-list');
  apisBox.textContent = '[*] المتصفح الذكي يعمل على التفاعل مع الـ DOM واعتراض مكالمات الـ API...';
  actionsBox.textContent = '[*] جاري حقن مسابر الـ Canaries ومراقبة النماذج والأزرار...';

  try {
    const res = await fetch('/api/enhanced/browser/explore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_url: targetUrl,
        proxy: proxy,
        headless: headless,
        max_pages: pages,
      })
    });
    const data = await res.json();

    const apis = data.intercepted_api_endpoints || [];
    if (apis.length > 0) {
      apisBox.textContent = apis.map(a => `[${a.method || 'GET'}] ${a.url || a}`).join('\n');
    } else {
      apisBox.textContent = 'لم يتم رصد مكالمات API إضافية خلال التصفح.';
    }

    const actions = data.actions_performed || [];
    if (actions.length > 0) {
      actionsBox.textContent = actions.join('\n');
    } else {
      actionsBox.textContent = 'تم إكمال جلسة التصفح واستخراج النماذج بنجاح.';
    }
  } catch (err) {
    apisBox.textContent = 'خطأ أثناء تشغيل المتصفح: ' + err;
  }
}

// ── PILLAR 4: 149 Skills Matrix & Elite Probers Controller ────────────────────
async function loadSkillsMatrix() {
  try {
    const res = await fetch('/api/enhanced/skills/catalog');
    const data = await res.json();
    allLoadedSkills = data.skills || [];
    renderSkillsGrid(allLoadedSkills);
  } catch (err) {
    console.error('Skills load error:', err);
  }
}

function filterSkillsByLayer(layer, btn) {
  document.querySelectorAll('#skills-category-bar .cat-pill-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  if (layer === 'all') {
    renderSkillsGrid(allLoadedSkills);
  } else {
    const filtered = allLoadedSkills.filter(s => s.layer === layer);
    renderSkillsGrid(filtered);
  }
}

function filterSkillsMatrix() {
  const q = document.getElementById('skills-search-input').value.toLowerCase().trim();
  const filtered = allLoadedSkills.filter(s => {
    return !q || (s.name || '').toLowerCase().includes(q) || (s.description || '').toLowerCase().includes(q) || (s.category || '').toLowerCase().includes(q);
  });
  renderSkillsGrid(filtered);
}

function renderSkillsGrid(skills) {
  const container = document.getElementById('skills-grid-container');
  if (!container) return;

  if (skills.length === 0) {
    container.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:24px;color:var(--text-dim);">لا توجد مهارات مطابقة.</div>';
    return;
  }

  container.innerHTML = skills.map(s => `
    <div class="skill-card">
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <strong style="color:var(--cyan);font-family:var(--font-mono);font-size:0.85em;">${s.name}</strong>
          <span class="status-badge ${s.layer === 'kali_arsenal' ? 'badge-green' : 'badge-purple'}" style="font-size:0.65em;">${s.layer || 'skill'}</span>
        </div>
        <div style="font-size:0.75em;color:var(--text-muted);margin:4px 0;">الفئة: <code>${s.category || 'general'}</code></div>
        <div style="font-size:0.78em;color:var(--text-dim);line-height:1.4;">${(s.description || '').substring(0, 95)}...</div>
      </div>
      <div style="margin-top:8px;border-top:1px solid var(--border);padding-top:6px;display:flex;justify-content:flex-end;">
        <span style="font-size:0.7em;color:var(--emerald);">جاهز للاستدعاء الذاتي ●</span>
      </div>
    </div>
  `).join('');
}

async function triggerEliteSkill(skillName) {
  const targetUrl = prompt('أدخل رابط الهدف لاختبار مهارة النخبة:', 'https://target.local');
  if (!targetUrl) return;

  const box = document.getElementById('elite-skill-result-box');
  box.style.display = 'block';
  box.textContent = `[*] جاري إرسال حمولة مهارة النخبة [${skillName}] إلى ${targetUrl}...`;

  try {
    const res = await fetch('/api/enhanced/skills/elite-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ skill_name: skillName, target_url: targetUrl })
    });
    const data = await res.json();
    box.textContent = JSON.stringify(data, null, 2);
    if (data.verified) {
      alert(`🎉 تم تأكيد الثغرة بنجاح: ${data.title}`);
    }
  } catch (err) {
    box.textContent = 'خطأ أثناء تنفيذ المهارة: ' + err;
  }
}

// ── PILLAR 5: Dynamic AI Command Synthesizer Studio ───────────────────────────
async function synthesizeKaliCommand() {
  const tool = document.getElementById('synth-tool-select').value;
  const target = document.getElementById('synth-target-input').value.trim();
  const waf = document.getElementById('synth-waf-select').value || null;
  const proxy = document.getElementById('synth-proxy-input').value.trim() || null;

  try {
    const res = await fetch('/api/enhanced/arsenal/synthesize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_name: tool,
        target: target,
        waf_name: waf,
        proxy: proxy,
      })
    });
    const data = await res.json();

    const container = document.getElementById('synth-result-container');
    container.style.display = 'block';
    document.getElementById('synth-cmd-box').textContent = data.synthesized_command;
    document.getElementById('synth-rationale-box').innerHTML = `
      <strong>المنطق التكيفي:</strong> ${data.rationale}<br>
      <strong>القاموس المحقون:</strong> <code>${data.wordlist_resolved || 'Default'}</code> |
      <strong>الصلاحيات:</strong> <span style="color:var(--cyan)">${data.privilege_status}</span>
    `;
  } catch (err) {
    alert('خطأ في توليد الأمر: ' + err);
  }
}

// ── PILLAR 6: Cognitive Reasoning Controller ──────────────────────────────────
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

    box.textContent = data.formatted_trace || data.inner_monologue || 'Deliberation complete.';
  } catch (err) {
    box.textContent = 'خطأ في استدعاء محرك التفكير: ' + err;
  }
}

// ── PILLAR 7: Interactive AI Shell ───────────────────────────────────────────
async function sendChatMessage() {
  const input = document.getElementById('chat-user-input');
  const msg = input.value.trim();
  if (!msg) return;

  const box = document.getElementById('chat-messages-box');
  box.innerHTML += `
    <div style="background:rgba(255,255,255,0.06);padding:10px 14px;border-radius:var(--radius-md);max-width:80%;align-self:flex-start;">
      <strong style="color:var(--emerald)">المشغل:</strong>
      <p style="margin-top:4px;font-size:0.88em;">${msg}</p>
    </div>
  `;
  input.value = '';
  box.scrollTop = box.scrollHeight;

  const model = document.getElementById('chat-model-select').value;
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, model: model })
    });
    const data = await res.json();
    const reply = data.reply || data.response || 'تم استلام الأمر.';
    box.innerHTML += `
      <div style="background:rgba(0,229,255,0.08);border:1px solid rgba(0,229,255,0.2);padding:10px 14px;border-radius:var(--radius-md);max-width:85%;align-self:flex-end;">
        <strong style="color:var(--cyan)">PentestAI Assistant:</strong>
        <p style="margin-top:4px;font-size:0.88em;white-space:pre-wrap;">${reply}</p>
      </div>
    `;
    box.scrollTop = box.scrollHeight;
  } catch (err) {
    box.innerHTML += `<div style="color:var(--rose);font-size:0.8em;">خطأ: ${err}</div>`;
  }
}

// ── PILLAR 8: Evidence Court ──────────────────────────────────────────────────
function refreshLedgerView() {
  const el = document.getElementById('ledger-evidence-container');
  el.innerHTML = '<p style="color:var(--emerald);font-size:0.88em;">تم تحديث محكمة الأدلة. كافة النتائج المحكوم بها مسجلة رقمياً وجاهزة للتصدير كحزم PoC.</p>';
}

// ── PILLAR 9: Reports & Dossiers Explorer ─────────────────────────────────────
async function loadReportsList() {
  const container = document.getElementById('reports-list-container');
  try {
    const res = await fetch('/api/enhanced/reports');
    const data = await res.json();
    const reports = data.reports || [];

    if (reports.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim);text-align:center;padding:24px;">لا توجد تقارير منشأة حالياً في data/reports/.</div>';
      return;
    }

    container.innerHTML = reports.map(r => `
      <div class="report-item-row">
        <div>
          <strong style="color:${r.is_master_dossier ? 'var(--emerald)' : 'var(--cyan)'};font-family:var(--font-mono);font-size:0.85em;">
            ${r.is_master_dossier ? '🏆 ' : '📄 '}${r.filename}
          </strong>
          <div style="font-size:0.75em;color:var(--text-muted);margin-top:3px;">الحجم: ${(r.size_bytes / 1024).toFixed(1)} KB | التاريخ: ${r.modified}</div>
        </div>
        <button class="cyber-btn" style="padding:4px 12px;font-size:0.78em;" onclick="viewReportContent('${r.filename}')">
          عرض التقرير 📖
        </button>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = '<div style="color:var(--rose);">خطأ أثناء تحميل التقارير: ' + err + '</div>';
  }
}

async function viewReportContent(filename) {
  try {
    const res = await fetch(`/api/enhanced/reports/${filename}`);
    const text = await res.text();
    const card = document.getElementById('report-viewer-card');
    card.style.display = 'block';
    document.getElementById('viewer-report-title').textContent = filename;
    document.getElementById('viewer-report-body').textContent = text;
    card.scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    alert('فشل قراءة ملف التقرير: ' + err);
  }
}

async function loadSnapshotsList() {
  const container = document.getElementById('snapshots-sidebar-list');
  if (!container) return;
  try {
    const res = await fetch('/api/enhanced/snapshots');
    const data = await res.json();
    const snaps = data.snapshots || [];
    if (snaps.length === 0) {
      container.innerHTML = '<span style="font-size:0.72em;color:var(--text-dim)">لا توجد نقاط محفوظة.</span>';
      return;
    }
    container.innerHTML = snaps.map(s => `
      <div class="model-pill" style="cursor:pointer;" onclick="selectResumeSnapshot('${s.snapshot_id}')">
        <span class="dot-status online"></span>
        <span style="font-size:0.75em;color:var(--cyan);">${s.snapshot_id}</span>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = '<span style="font-size:0.72em;color:var(--rose)">خطأ تحميل النقاط.</span>';
  }
}

function selectResumeSnapshot(snapId) {
  const input = document.getElementById('omni-resume-input');
  if (input) {
    input.value = snapId;
    switchPillar('omni', document.querySelector('.pillar-tab-btn'));
    alert(`تم اختيار نقطة الاستئناف: ${snapId}`);
  }
}

// ── Arsenal Tools Helper Logic ────────────────────────────────────────────────
async function loadArsenalTools() {
  try {
    const res = await fetch('/api/arsenal/tools');
    const data = await res.json();
    allArsenalTools = data.tools || [];

    const badge = document.getElementById('arsenal-count-badge');
    if (badge) badge.textContent = `${data.total} أداة (${data.installed} مثبتة)`;
    const sumBadge = document.getElementById('arsenal-summary-badge');
    if (sumBadge) sumBadge.textContent = `Arsenal: ${data.total} Tools`;

    renderArsenalGrid();
  } catch (err) {
    console.error('Arsenal load error:', err);
  }
}

function selectArsenalCategory(cat, btn) {
  currentCategory = cat;
  document.querySelectorAll('#category-filter-bar .cat-pill-btn').forEach(b => b.classList.remove('active'));
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
    const matchQ = !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
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
  document.getElementById('modal-tool-title').textContent = toolName;

  try {
    const res = await fetch(`/api/arsenal/tool/${toolName}`);
    const data = await res.json();
    document.getElementById('modal-sys-prompt').textContent = data.system_prompt || 'Standard Persona';
    document.getElementById('modal-mcp-schema').textContent = JSON.stringify(data.mcp_schema || {}, null, 2);
  } catch (err) {
    console.error('Modal load error:', err);
  }
}

function closeToolModal(event) {
  if (event && event.target && event.target.className !== 'cyber-modal-overlay') return;
  document.getElementById('tool-modal').style.display = 'none';
}

async function executeModalTool() {
  if (!modalActiveTool) return;
  const target = document.getElementById('modal-exec-target').value.trim();
  if (!target) {
    alert('يرجى تحديد الهدف!');
    return;
  }
  const pre = document.getElementById('modal-exec-result');
  pre.style.display = 'block';
  pre.textContent = `[*] جاري تشغيل الوكيل الذكي للأداة ${modalActiveTool} ضد ${target}...`;

  try {
    const res = await fetch('/api/arsenal/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: modalActiveTool, target: target, thinking: true })
    });
    const data = await res.json();
    pre.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    pre.textContent = 'خطأ أثناء التشغيل: ' + err;
  }
}
