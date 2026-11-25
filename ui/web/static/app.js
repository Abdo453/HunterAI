'use strict';

/* HunterAI Control Center JS — Hardened against XSS, native dialogs, and background polling */

let currentPillar = 'omni';
let activeMasterMissionId = null;
let masterPollHandle = null;
let masterPollAbort = null;
let allArsenalTools = [];
let currentCategory = 'all';
let modalActiveTool = null;
let allLoadedSkills = [];
let _activeDorksData = null;

function escapeHtml(value) {
  if (window.HunterCore && typeof window.HunterCore.escapeHtml === 'function') {
    return window.HunterCore.escapeHtml(value);
  }
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeHref(url) {
  if (window.HunterCore && typeof window.HunterCore.safeHref === 'function') {
    return window.HunterCore.safeHref(url);
  }
  const s = String(url || '').trim();
  if (/^https?:\/\//i.test(s) || s.startsWith('/')) return s;
  return '#';
}

function uiEl(tag, attrs, children) {
  if (window.HunterCore && typeof window.HunterCore.el === 'function') {
    return window.HunterCore.el(tag, attrs, children);
  }
  const node = document.createElement(tag);
  if (attrs) {
    Object.entries(attrs).forEach(([k, v]) => {
      if (v === null || v === undefined || v === false) return;
      if (k === 'class' || k === 'className') node.className = String(v);
      else if (k === 'style' && typeof v === 'object') Object.assign(node.style, v);
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
      else node.setAttribute(k, String(v));
    });
  }
  if (children !== undefined && children !== null) {
    const arr = Array.isArray(children) ? children : [children];
    arr.forEach((c) => {
      if (c === null || c === undefined) return;
      node.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    });
  }
  return node;
}

function showUiNotice(msg, tone) {
  const text = String(msg || '');
  if (window.HunterCore && typeof window.HunterCore.toast === 'function') {
    window.HunterCore.toast(text, tone || 'info');
  } else {
    console.info('[HunterAI Notice]', tone || 'info', text);
  }
}

function openTargetPromptModal(titleText, defaultVal) {
  return new Promise((resolve) => {
    const existing = document.getElementById('hunter-app-prompt-modal');
    if (existing) existing.remove();

    const prevFocus = document.activeElement;
    const input = uiEl('input', {
      type: 'text',
      class: 'ltr-isolate',
      value: defaultVal || 'https://target.local',
      style: {
        width: '100%',
        minHeight: '44px',
        padding: '10px 12px',
        borderRadius: '8px',
        border: '1px solid #30363d',
        background: '#0d1117',
        color: '#e6edf3',
        marginTop: '10px',
      },
    });

    function cleanup(val) {
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
      resolve(val);
    }

    function onKey(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        cleanup(null);
      } else if (e.key === 'Enter' && document.activeElement === input) {
        e.preventDefault();
        cleanup(input.value.trim() || null);
      }
    }

    const cancelBtn = uiEl('button', {
      type: 'button',
      class: 'cyber-btn',
      style: { minHeight: '44px', padding: '8px 14px' },
      onClick: () => cleanup(null),
    }, 'إلغاء');

    const okBtn = uiEl('button', {
      type: 'button',
      class: 'cyber-btn',
      style: { minHeight: '44px', padding: '8px 16px', background: '#2563eb', color: '#ffffff', borderColor: '#2563eb' },
      onClick: () => cleanup(input.value.trim() || null),
    }, 'تنفيذ');

    const card = uiEl('div', {
      role: 'dialog',
      'aria-modal': 'true',
      style: {
        width: 'min(440px, 92vw)',
        background: '#161b22',
        color: '#e6edf3',
        border: '1px solid #30363d',
        borderRadius: '12px',
        padding: '18px',
        boxShadow: '0 16px 40px rgba(0, 0, 0, 0.45)',
      },
      onClick: (e) => e.stopPropagation(),
    }, [
      uiEl('div', { style: { fontWeight: '700', fontSize: '1rem' } }, titleText),
      input,
      uiEl('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '14px' } }, [cancelBtn, okBtn]),
    ]);

    const overlay = uiEl('div', {
      id: 'hunter-app-prompt-modal',
      style: {
        position: 'fixed',
        inset: '0',
        background: 'rgba(2, 6, 23, 0.72)',
        zIndex: '9999',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      },
      onClick: () => cleanup(null),
    }, [card]);

    document.addEventListener('keydown', onKey);
    document.body.appendChild(overlay);
    setTimeout(() => input.focus(), 0);
  });
}

function openInfoModal(titleText, bodyText) {
  const existing = document.getElementById('hunter-app-info-modal');
  if (existing) existing.remove();

  const prevFocus = document.activeElement;
  function close() {
    document.removeEventListener('keydown', onKey);
    overlay.remove();
    if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
  }
  function onKey(e) {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  }

  const closeBtn = uiEl('button', {
    type: 'button',
    class: 'cyber-btn',
    style: { minHeight: '44px', padding: '8px 16px' },
    onClick: close,
  }, 'إغلاق');

  const card = uiEl('div', {
    role: 'dialog',
    'aria-modal': 'true',
    style: {
      width: 'min(580px, 92vw)',
      background: '#161b22',
      color: '#e6edf3',
      border: '1px solid #30363d',
      borderRadius: '12px',
      padding: '18px',
      boxShadow: '0 16px 40px rgba(0, 0, 0, 0.45)',
    },
    onClick: (e) => e.stopPropagation(),
  }, [
    uiEl('div', { style: { fontWeight: '700', fontSize: '1rem', marginBottom: '10px' } }, titleText),
    uiEl('pre', {
      class: 'ltr-isolate',
      dir: 'ltr',
      style: {
        margin: '0',
        padding: '12px',
        background: '#0d1117',
        border: '1px solid #30363d',
        borderRadius: '8px',
        maxHeight: '320px',
        overflow: 'auto',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.82em',
      },
    }, String(bodyText || '')),
    uiEl('div', { style: { display: 'flex', justifyContent: 'flex-end', marginTop: '12px' } }, [closeBtn]),
  ]);

  const overlay = uiEl('div', {
    id: 'hunter-app-info-modal',
    style: {
      position: 'fixed',
      inset: '0',
      background: 'rgba(2, 6, 23, 0.72)',
      zIndex: '9999',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
    },
    onClick: close,
  }, [card]);

  document.addEventListener('keydown', onKey);
  document.body.appendChild(overlay);
  setTimeout(() => closeBtn.focus(), 0);
}

// ── Document Ready ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadArsenalTools();
  loadSnapshotsList();
  loadReportsList();
  loadSkillsMatrix();
  if (window.HunterCore && typeof window.HunterCore.createVisibilityPoller === 'function') {
    window.HunterCore.createVisibilityPoller(updateGPUStatus, 5000, { immediate: false });
  }
});

// ── Navigation Controller ─────────────────────────────────────────────────────
function switchPillar(pillar, btn) {
  currentPillar = pillar;
  document.querySelectorAll('.pillar-tab-btn').forEach((b) => b.classList.remove('active'));
  document.querySelectorAll('.pillar-viewport').forEach((v) => v.classList.remove('active'));

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
  el.textContent = '';
  const defs = [
    { k: 'qwen2.5-coder', l: 'Qwen2.5-Coder:14B' },
    { k: 'whiterabbitneo', l: 'WhiteRabbitNeo (Sec LLM)' },
    { k: 'xploiter', l: 'xploiter/pentester' },
  ];
  defs.forEach((m) => {
    const on = models.some((x) => String(x || '').toLowerCase().includes(m.k));
    el.appendChild(uiEl('div', { class: 'model-pill' }, [
      uiEl('span', { class: `dot-status ${on ? 'online' : ''}` }),
      uiEl('span', { style: { color: on ? '#fff' : '#666' } }, m.l),
    ]));
  });
}

function renderApiKeys(keys) {
  const el = document.getElementById('api-list');
  if (!el) return;
  el.textContent = '';
  Object.entries(keys || {}).forEach(([k, v]) => {
    el.appendChild(uiEl('div', { class: 'model-pill' }, [
      uiEl('span', { class: `dot-status ${v ? 'online' : ''}` }),
      uiEl('span', { style: { color: v ? '#fff' : '#666' } }, k),
    ]));
  });
}

function stopMasterMissionPoller() {
  if (masterPollHandle && typeof masterPollHandle.stop === 'function') {
    masterPollHandle.stop();
  }
  masterPollHandle = null;
  if (masterPollAbort) {
    try {
      masterPollAbort.abort();
    } catch (_) {}
    masterPollAbort = null;
  }
}

function updateGPUStatus(signal) {
  const fetchOpts = signal ? { signal: signal } : undefined;
  fetch('/api/status', fetchOpts).then((r) => r.json()).then((d) => {
    const freeEl = document.getElementById('gpu-state');
    const modelEl = document.getElementById('gpu-model');
    if (!freeEl || !modelEl) return;
    const loaded = Array.isArray(d.loaded_models) ? d.loaded_models : [];
    const local = Array.isArray(d.local_models) ? d.local_models : [];
    const configuredCloud = Object.entries(d.api_keys || {})
      .filter(([, ok]) => Boolean(ok))
      .map(([name]) => name);

    if (loaded.length > 0) {
      freeEl.textContent = 'ACTIVE';
      freeEl.className = 'gpu-metric-val';
      freeEl.style.color = 'var(--cyan)';
      modelEl.textContent = String(loaded[0]);
    } else if (local.length > 0) {
      freeEl.textContent = 'IDLE';
      freeEl.className = 'gpu-metric-val free';
      freeEl.style.color = '';
      modelEl.textContent = `Idle (${local[0]} available)`;
    } else if (configuredCloud.length > 0) {
      freeEl.textContent = 'LOCAL OFFLINE';
      freeEl.className = 'gpu-metric-val';
      freeEl.style.color = 'var(--amber)';
      modelEl.textContent = `Cloud ready (${configuredCloud.join(', ')})`;
    } else {
      freeEl.textContent = 'OFFLINE';
      freeEl.className = 'gpu-metric-val';
      freeEl.style.color = 'var(--rose)';
      modelEl.textContent = 'No model loaded';
    }
  }).catch((err) => {
    if (err && err.name === 'AbortError') return;
    const freeEl = document.getElementById('gpu-state');
    const modelEl = document.getElementById('gpu-model');
    if (!freeEl || !modelEl) return;
    freeEl.textContent = 'OFFLINE';
    freeEl.className = 'gpu-metric-val';
    freeEl.style.color = 'var(--rose)';
    modelEl.textContent = 'Status unavailable';
  });
}

// ── PILLAR 1: Master One-Command-For-Everything Controller ────────────────────
async function launchMasterAllAssessment() {
  const target = document.getElementById('omni-target-input')?.value.trim() || '';
  const scopeStr = document.getElementById('omni-scope-input')?.value.trim() || '';
  const platform = document.getElementById('omni-platform-select')?.value || 'hackerone';
  const proxy = document.getElementById('omni-proxy-input')?.value.trim() || null;
  const burpFile = document.getElementById('omni-burpfile-input')?.value.trim() || null;
  const resume = document.getElementById('omni-resume-input')?.value.trim() || null;
  const cycles = parseInt(document.getElementById('omni-cycles-input')?.value || '10', 10) || 10;

  const authChecked = Boolean(document.getElementById('omni-auth-chk')?.checked);
  const selfOpChecked = Boolean(document.getElementById('omni-selfop-chk')?.checked);
  const fallbackChecked = Boolean(document.getElementById('omni-fallback-chk')?.checked);

  if (!target) {
    showUiNotice('يرجى إدخال الهدف!', 'warning');
    return;
  }

  const pill = document.getElementById('mission-status-pill');
  if (pill) {
    pill.textContent = 'جاري إطلاق الفحص الشامل...';
    pill.className = 'status-badge badge-blue';
  }

  try {
    const res = await fetch('/api/enhanced/omni/launch-all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        scope: scopeStr || undefined,
        authorized: authChecked,
        platform: platform,
        proxy: proxy,
        burp_file: burpFile,
        resume: resume,
        max_cycles: cycles,
        coverage: 0.85,
        force_fallback: fallbackChecked,
        self_operate: selfOpChecked,
      }),
    });
    const data = await res.json();
    if (data.mission_id) {
      activeMasterMissionId = data.mission_id;
      if (pill) {
        pill.textContent = `نشط: ${activeMasterMissionId}`;
        pill.className = 'status-badge badge-green';
      }
      stopMasterMissionPoller();
      if (window.HunterCore && typeof window.HunterCore.createVisibilityPoller === 'function') {
        masterPollHandle = window.HunterCore.createVisibilityPoller((signal) => {
          if (activeMasterMissionId) {
            return pollMasterMission(activeMasterMissionId, signal);
          }
        }, 2500, { immediate: false });
      } else {
        masterPollAbort = typeof AbortController === 'function' ? new AbortController() : null;
        const scheduleNext = () => {
          if (!activeMasterMissionId || (masterPollAbort && masterPollAbort.signal.aborted)) return;
          const tid = setTimeout(async () => {
            if (!activeMasterMissionId || (masterPollAbort && masterPollAbort.signal.aborted)) return;
            if (!document.hidden) {
              await pollMasterMission(activeMasterMissionId, masterPollAbort ? masterPollAbort.signal : undefined);
            }
            scheduleNext();
          }, 2500);
          if (masterPollAbort) {
            masterPollAbort.signal.addEventListener('abort', () => clearTimeout(tid), { once: true });
          }
        };
        scheduleNext();
      }
    }
  } catch (err) {
    if (pill) pill.textContent = 'فشل الإطلاق';
    showUiNotice('خطأ في إطلاق المهمة: ' + err, 'error');
  }
}

async function pollMasterMission(missionId, signal) {
  try {
    const fetchOpts = signal ? { signal: signal } : undefined;
    const res = await fetch(`/api/enhanced/omni/status/${encodeURIComponent(missionId)}`, fetchOpts);
    const data = await res.json();

    const curPhase = data.current_phase || 'INIT';
    const phaseEl = document.getElementById('active-phase-name');
    if (phaseEl) phaseEl.textContent = `Phase: ${curPhase}`;
    const steps = ['RECON', 'NETWORK', 'WEB', 'API', 'JAVASCRIPT', 'VERIFICATION', 'ADJUDICATION', 'REPORT'];
    const curIdx = steps.indexOf(curPhase);
    steps.forEach((s, i) => {
      const stepEl = document.getElementById(`step-${s}`);
      if (!stepEl) return;
      stepEl.className = 'ooda-step';
      if (i < curIdx) stepEl.classList.add('done');
      else if (i === curIdx) stepEl.classList.add('active');
    });

    const cov = Number(data.coverage_pct || 0.0);
    const covEl = document.getElementById('metric-coverage');
    if (covEl) covEl.textContent = `${cov.toFixed(1)}%`;
    const barEl = document.getElementById('metric-coverage-bar');
    if (barEl) barEl.style.width = `${Math.min(100, cov)}%`;
    const findEl = document.getElementById('metric-findings');
    if (findEl) findEl.textContent = String(data.confirmed_findings_count || 0);
    const elapsedEl = document.getElementById('metric-elapsed');
    if (elapsedEl) elapsedEl.textContent = `${data.elapsed_secs || 0}s`;
    const progEl = document.getElementById('metric-target-progress');
    if (progEl) progEl.textContent = `Target: ${data.target_progress || '1/1'}`;

    const findings = data.confirmed_findings || [];
    const tbody = document.getElementById('omni-findings-tbody');
    if (tbody && findings.length > 0) {
      tbody.textContent = '';
      findings.forEach((f, i) => {
        const evidenceText = f.evidence ? String(f.evidence) : 'Confirmed';
        const pocBtn = uiEl('button', {
          type: 'button',
          class: 'cyber-btn',
          style: { padding: '4px 10px', fontSize: '0.75em', minHeight: '44px' },
          onClick: () => openInfoModal(`تفاصيل الإثبات #FIND-${i + 1}`, evidenceText),
        }, 'حزمة PoC');

        const tr = uiEl('tr', null, [
          uiEl('td', { class: 'ltr-isolate', style: { fontFamily: 'var(--font-mono)', fontWeight: 'bold', color: 'var(--cyan)' } }, `#FIND-${i + 1}`),
          uiEl('td', null, [uiEl('span', { class: 'risk-tag risk-critical' }, f.vuln_class || 'Vulnerability')]),
          uiEl('td', { class: 'ltr-isolate', style: { fontFamily: 'var(--font-mono)', fontSize: '0.85em' } }, f.target || 'target'),
          uiEl('td', null, [uiEl('span', { class: 'status-badge badge-green' }, f.verdict || 'CONFIRMED')]),
          uiEl('td', null, [uiEl('strong', null, `${((f.confidence || 0.95) * 100).toFixed(0)}%`)]),
          uiEl('td', null, [pocBtn]),
        ]);
        tbody.appendChild(tr);
      });
    }

    if (data.dossiers && data.dossiers.length > 0) {
      const container = document.getElementById('master-dossier-pill-container');
      if (container) {
        const latestDossier = String(data.dossiers[data.dossiers.length - 1]);
        const filename = latestDossier.split(/[\\/]/).pop();
        container.textContent = '';
        container.appendChild(uiEl('button', {
          type: 'button',
          class: 'cyber-btn',
          style: { background: 'var(--emerald)', color: '#04060a', fontWeight: 'bold', padding: '6px 14px', minHeight: '44px' },
          onClick: () => viewReportContent(filename),
        }, 'عرض تقرير الـ Dossier الشامل'));
      }
    }

    if (data.status === 'COMPLETED' || data.status === 'FAILED') {
      stopMasterMissionPoller();
      const pill = document.getElementById('mission-status-pill');
      if (pill) {
        pill.textContent = data.status === 'COMPLETED' ? 'اكتمل الفحص الشامل بنجاح' : 'انتهت المهمة';
      }
      loadReportsList();
      loadSnapshotsList();
    }
  } catch (err) {
    if (err && err.name === 'AbortError') return;
    console.error('Master poll error:', err);
  }
}

// ── PILLAR 2: Burp Suite Deep Log Inspector Controller ────────────────────────
async function executeBurpInspection() {
  const source = document.getElementById('burp-source-input')?.value.trim() || '';
  const target = document.getElementById('burp-target-input')?.value.trim() || '';
  const port = parseInt(document.getElementById('burp-port-input')?.value || '8085', 10) || 8085;
  const pasted = document.getElementById('burp-content-paste')?.value.trim() || '';

  const container = document.getElementById('burp-findings-container');
  if (!container) return;
  container.textContent = '';
  container.appendChild(uiEl('div', { style: { color: 'var(--cyan)', textAlign: 'center', padding: '24px' } },
    'جاري فحص وتدقيق سجلات Burp واستخراج الأسرار وتصنيف البارامترات...'));

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
      }),
    });
    const data = await res.json();
    if (!data.success) {
      container.textContent = '';
      container.appendChild(uiEl('div', { style: { color: 'var(--rose)', padding: '14px' } },
        `خطأ في الفحص: ${data.error || 'فشل الفحص'}`));
      return;
    }

    const intEl = document.getElementById('burp-stat-interactions');
    if (intEl) intEl.textContent = String(data.total_interactions || 0);
    const epEl = document.getElementById('burp-stat-endpoints');
    if (epEl) epEl.textContent = String((data.discovered_endpoints || []).length);
    const sigEl = document.getElementById('burp-stat-signals');
    if (sigEl) sigEl.textContent = String(data.total_findings || 0);

    const findings = data.findings || [];
    container.textContent = '';
    if (findings.length === 0) {
      container.appendChild(uiEl('div', { style: { color: 'var(--emerald)', padding: '20px', textAlign: 'center' } },
        'لم يتم العثور على أسرار مسربة أو أخطاء مباشرة في السجلات المفحوصة.'));
    } else {
      findings.forEach((f) => {
        const sevColor = f.severity === 'Critical' ? 'var(--rose)' : f.severity === 'High' ? 'var(--amber)' : 'var(--cyan)';
        const card = uiEl('div', {
          style: {
            background: 'rgba(0, 0, 0, 0.35)',
            border: '1px solid var(--border)',
            borderLeft: `4px solid ${sevColor}`,
            borderRadius: 'var(--radius-sm)',
            padding: '12px',
          },
        }, [
          uiEl('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
            uiEl('strong', { style: { color: sevColor } }, f.title || 'Finding'),
            uiEl('span', { class: 'risk-tag', style: { background: sevColor, color: '#04060a', fontWeight: 'bold' } }, f.severity || 'Info'),
          ]),
          uiEl('div', { style: { fontSize: '0.8em', color: 'var(--text-muted)', margin: '4px 0' } }, [
            'نوع الثغرة: ',
            uiEl('code', { class: 'ltr-isolate', dir: 'ltr' }, f.vuln_type || ''),
            ' | الرابط: ',
            uiEl('code', { class: 'ltr-isolate', dir: 'ltr' }, f.url || ''),
          ]),
          uiEl('div', {
            class: 'ltr-isolate',
            dir: 'ltr',
            style: {
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75em',
              background: '#03060d',
              padding: '8px',
              borderRadius: '4px',
              color: '#8fbcbb',
              marginTop: '6px',
              whiteSpace: 'pre-wrap',
            },
          }, f.evidence || ''),
        ]);
        container.appendChild(card);
      });
    }

    const dlBtn = document.getElementById('burp-download-report-btn');
    if (dlBtn && data.output_files && data.output_files['burp_log_analysis_report.md']) {
      dlBtn.textContent = '';
      dlBtn.appendChild(uiEl('button', {
        type: 'button',
        class: 'cyber-btn',
        style: { minHeight: '44px' },
        onClick: () => viewReportContent('burp_log_analysis_report.md'),
      }, 'استعراض التقرير المكتبي الكامل'));
    }
  } catch (err) {
    container.textContent = '';
    container.appendChild(uiEl('div', { style: { color: 'var(--rose)', padding: '14px' } }, `خطأ اتصال: ${err}`));
  }
}

// ── PILLAR 3: Active AI Browser & DOM XSS Studio ──────────────────────────────
async function launchAIBrowserSession() {
  const targetUrl = document.getElementById('browser-target-input')?.value.trim() || '';
  const proxy = document.getElementById('browser-proxy-input')?.value.trim() || null;
  const pages = parseInt(document.getElementById('browser-pages-input')?.value || '5', 10) || 5;
  const headless = Boolean(document.getElementById('browser-headless-chk')?.checked);

  if (!targetUrl) {
    showUiNotice('يرجى إدخال رابط الهدف للمتصفح!', 'warning');
    return;
  }

  const apisBox = document.getElementById('browser-apis-list');
  const actionsBox = document.getElementById('browser-actions-list');
  if (apisBox) apisBox.textContent = '[*] المتصفح الذكي يعمل على التفاعل مع الـ DOM واعتراض مكالمات الـ API...';
  if (actionsBox) actionsBox.textContent = '[*] جاري حقن مسابر الـ Canaries ومراقبة النماذج والأزرار...';

  try {
    const res = await fetch('/api/enhanced/browser/explore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_url: targetUrl,
        proxy: proxy,
        headless: headless,
        max_pages: pages,
      }),
    });
    const data = await res.json();

    const apis = data.intercepted_api_endpoints || [];
    if (apisBox) {
      apisBox.textContent = apis.length > 0
        ? apis.map((a) => `[${a.method || 'GET'}] ${a.url || a}`).join('\n')
        : 'لم يتم رصد مكالمات API إضافية خلال التصفح.';
    }

    const actions = data.actions_performed || [];
    if (actionsBox) {
      actionsBox.textContent = actions.length > 0
        ? actions.join('\n')
        : 'تم إكمال جلسة التصفح واستخراج النماذج بنجاح.';
    }
  } catch (err) {
    if (apisBox) apisBox.textContent = 'خطأ أثناء تشغيل المتصفح: ' + err;
  }
}

// ── PILLAR 4: Skills Matrix & Elite Probers Controller ────────────────────────
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
  document.querySelectorAll('#skills-category-bar .cat-pill-btn').forEach((b) => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  if (layer === 'all') {
    renderSkillsGrid(allLoadedSkills);
  } else {
    renderSkillsGrid(allLoadedSkills.filter((s) => s.layer === layer));
  }
}

function filterSkillsMatrix() {
  const q = (document.getElementById('skills-search-input')?.value || '').toLowerCase().trim();
  const filtered = allLoadedSkills.filter((s) => (
    !q
    || (s.name || '').toLowerCase().includes(q)
    || (s.description || '').toLowerCase().includes(q)
    || (s.category || '').toLowerCase().includes(q)
  ));
  renderSkillsGrid(filtered);
}

function renderSkillsGrid(skills) {
  const container = document.getElementById('skills-grid-container');
  if (!container) return;
  container.textContent = '';

  if (skills.length === 0) {
    container.appendChild(uiEl('div', { style: { gridColumn: '1/-1', textAlign: 'center', padding: '24px', color: 'var(--text-dim)' } },
      'لا توجد مهارات مطابقة.'));
    return;
  }

  skills.forEach((s) => {
    const badgeCls = s.layer === 'kali_arsenal' ? 'badge-green' : 'badge-purple';
    const desc = String(s.description || '').substring(0, 95) + '...';
    const card = uiEl('div', { class: 'skill-card' }, [
      uiEl('div', null, [
        uiEl('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
          uiEl('strong', { class: 'ltr-isolate', style: { color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.85em' } }, s.name || ''),
          uiEl('span', { class: `status-badge ${badgeCls}`, style: { fontSize: '0.65em' } }, s.layer || 'skill'),
        ]),
        uiEl('div', { style: { fontSize: '0.75em', color: 'var(--text-muted)', margin: '4px 0' } }, [
          'الفئة: ',
          uiEl('code', { class: 'ltr-isolate' }, s.category || 'general'),
        ]),
        uiEl('div', { style: { fontSize: '0.78em', color: 'var(--text-dim)', lineHeight: '1.4' } }, desc),
      ]),
      uiEl('div', { style: { marginTop: '8px', borderTop: '1px solid var(--border)', paddingTop: '6px', display: 'flex', justifyContent: 'flex-end' } }, [
        uiEl('span', { style: { fontSize: '0.7em', color: 'var(--emerald)' } }, 'جاهز للاستدعاء الذاتي ●'),
      ]),
    ]);
    container.appendChild(card);
  });
}

async function triggerEliteSkill(skillName) {
  const targetUrl = await openTargetPromptModal('أدخل رابط الهدف لاختبار مهارة النخبة:', 'https://target.local');
  if (!targetUrl) return;

  const box = document.getElementById('elite-skill-result-box');
  if (box) {
    box.style.display = 'block';
    box.classList.add('ltr-isolate');
    box.setAttribute('dir', 'ltr');
    box.textContent = `[*] Running elite skill [${skillName}] on ${targetUrl}...`;
  }

  try {
    const res = await fetch('/api/enhanced/skills/elite-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ skill_name: skillName, target_url: targetUrl }),
    });
    const data = await res.json();
    if (box) box.textContent = JSON.stringify(data, null, 2);
    if (data.verified) {
      showUiNotice(`تم تأكيد الثغرة بنجاح: ${data.title}`, 'success');
    } else {
      showUiNotice(data.message || 'اكتمل فحص المهارة', 'info');
    }
  } catch (err) {
    if (box) box.textContent = 'خطأ أثناء تنفيذ المهارة: ' + err;
    showUiNotice('خطأ أثناء تنفيذ المهارة: ' + err, 'error');
  }
}

// ── PILLAR 5: Dynamic AI Command Synthesizer Studio ───────────────────────────
async function synthesizeKaliCommand() {
  const tool = document.getElementById('synth-tool-select')?.value || '';
  const target = document.getElementById('synth-target-input')?.value.trim() || '';
  const waf = document.getElementById('synth-waf-select')?.value || null;
  const proxy = document.getElementById('synth-proxy-input')?.value.trim() || null;

  try {
    const res = await fetch('/api/enhanced/arsenal/synthesize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_name: tool,
        target: target,
        waf_name: waf,
        proxy: proxy,
      }),
    });
    const data = await res.json();

    const container = document.getElementById('synth-result-container');
    if (container) container.style.display = 'block';
    const cmdBox = document.getElementById('synth-cmd-box');
    if (cmdBox) {
      cmdBox.classList.add('ltr-isolate');
      cmdBox.setAttribute('dir', 'ltr');
      cmdBox.textContent = data.synthesized_command || '';
    }
    const rationaleBox = document.getElementById('synth-rationale-box');
    if (rationaleBox) {
      rationaleBox.textContent = '';
      rationaleBox.appendChild(uiEl('strong', null, 'المنطق التكيفي: '));
      rationaleBox.appendChild(document.createTextNode(String(data.rationale || '')));
      rationaleBox.appendChild(document.createElement('br'));
      rationaleBox.appendChild(uiEl('strong', null, 'القاموس المحقون: '));
      rationaleBox.appendChild(uiEl('code', { class: 'ltr-isolate' }, data.wordlist_resolved || 'Default'));
      rationaleBox.appendChild(document.createTextNode(' | '));
      rationaleBox.appendChild(uiEl('strong', null, 'الصلاحيات: '));
      rationaleBox.appendChild(uiEl('span', { style: { color: 'var(--cyan)' } }, data.privilege_status || 'user'));
    }
  } catch (err) {
    showUiNotice('خطأ في توليد الأمر: ' + err, 'error');
  }
}

// ── PILLAR 6: Cognitive Reasoning Controller ──────────────────────────────────
async function runCognitiveDeliberation() {
  const target = document.getElementById('cog-target-input')?.value.trim() || '';
  const obj = document.getElementById('cog-obj-input')?.value.trim() || '';
  const box = document.getElementById('inner-monologue-box');

  if (box) box.textContent = '[*] جاري استدعاء محرك المداولة المعرفية وتحليل الفرضيات...';

  try {
    const res = await fetch('/api/cognitive/deliberate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target, objective: obj, stakes: 'high' }),
    });
    const data = await res.json();

    const hyps = data.hypotheses || [];
    if (hyps.length > 0) {
      const h1t = document.getElementById('h1-text');
      const h1f = document.getElementById('h1-falsify');
      const h1c = document.getElementById('h1-conf');
      if (h1t) h1t.textContent = hyps[0].statement || '';
      if (h1f) h1f.textContent = hyps[0].refutation_criteria || '';
      if (h1c) h1c.textContent = `Confidence: ${((hyps[0].confidence || 0.6) * 100).toFixed(0)}%`;
    }
    if (hyps.length > 1) {
      const h2t = document.getElementById('h2-text');
      const h2f = document.getElementById('h2-falsify');
      const h2c = document.getElementById('h2-conf');
      if (h2t) h2t.textContent = hyps[1].statement || '';
      if (h2f) h2f.textContent = hyps[1].refutation_criteria || '';
      if (h2c) h2c.textContent = `Confidence: ${((hyps[1].confidence || 0.4) * 100).toFixed(0)}%`;
    }

    if (box) box.textContent = data.formatted_trace || data.inner_monologue || 'Deliberation complete.';
  } catch (err) {
    if (box) box.textContent = 'خطأ في استدعاء محرك التفكير: ' + err;
  }
}

// ── PILLAR 7: Interactive AI Shell ───────────────────────────────────────────
async function sendChatMessage() {
  const input = document.getElementById('chat-user-input');
  const msg = input ? input.value.trim() : '';
  if (!msg) return;

  const box = document.getElementById('chat-messages-box');
  if (box) {
    box.appendChild(uiEl('div', {
      style: {
        background: 'rgba(255, 255, 255, 0.06)',
        padding: '10px 14px',
        borderRadius: 'var(--radius-md)',
        maxWidth: '80%',
        alignSelf: 'flex-start',
      },
    }, [
      uiEl('strong', { style: { color: 'var(--emerald)' } }, 'المشغل:'),
      uiEl('p', { style: { marginTop: '4px', fontSize: '0.88em', whiteSpace: 'pre-wrap' } }, msg),
    ]));
    box.scrollTop = box.scrollHeight;
  }
  input.value = '';

  const model = document.getElementById('chat-model-select')?.value || 'auto';
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, model: model === 'auto' ? '' : model, provider: model === 'auto' ? 'auto' : undefined }),
    });
    const data = await res.json();
    const reply = data.reply || data.response || 'تم استلام الأمر.';
    if (box) {
      box.appendChild(uiEl('div', {
        style: {
          background: 'rgba(0, 229, 255, 0.08)',
          border: '1px solid rgba(0, 229, 255, 0.2)',
          padding: '10px 14px',
          borderRadius: 'var(--radius-md)',
          maxWidth: '85%',
          alignSelf: 'flex-end',
        },
      }, [
        uiEl('strong', { style: { color: 'var(--cyan)' } }, 'HunterAI Assistant:'),
        uiEl('p', { style: { marginTop: '4px', fontSize: '0.88em', whiteSpace: 'pre-wrap' } }, reply),
      ]));
      box.scrollTop = box.scrollHeight;
    }
  } catch (err) {
    if (box) {
      box.appendChild(uiEl('div', { style: { color: 'var(--rose)', fontSize: '0.8em' } }, `خطأ: ${err}`));
    }
  }
}

// ── PILLAR 8: Evidence Court ──────────────────────────────────────────────────
function refreshLedgerView() {
  const el = document.getElementById('ledger-evidence-container');
  if (!el) return;
  el.textContent = '';
  el.appendChild(uiEl('p', { style: { color: 'var(--emerald)', fontSize: '0.88em' } },
    'تم تحديث محكمة الأدلة. كافة النتائج المحكوم بها مسجلة رقمياً وجاهزة للتصدير كحزم PoC.'));
}

// ── PILLAR 9: Reports & Dossiers Explorer ─────────────────────────────────────
async function loadReportsList() {
  const container = document.getElementById('reports-list-container');
  if (!container) return;
  try {
    const res = await fetch('/api/enhanced/reports');
    const data = await res.json();
    const reports = data.reports || [];
    container.textContent = '';

    if (reports.length === 0) {
      container.appendChild(uiEl('div', { style: { color: 'var(--text-dim)', textAlign: 'center', padding: '24px' } },
        'لا توجد تقارير منشأة حالياً في data/reports/.'));
      return;
    }

    reports.forEach((r) => {
      const row = uiEl('div', { class: 'report-item-row' }, [
        uiEl('div', null, [
          uiEl('strong', {
            class: 'ltr-isolate',
            style: { color: r.is_master_dossier ? 'var(--emerald)' : 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.85em' },
          }, `${r.is_master_dossier ? '[Dossier] ' : ''}${r.filename}`),
          uiEl('div', { style: { fontSize: '0.75em', color: 'var(--text-muted)', marginTop: '3px' } },
            `الحجم: ${((r.size_bytes || 0) / 1024).toFixed(1)} KB | التاريخ: ${r.modified || '-'}`),
        ]),
        uiEl('button', {
          type: 'button',
          class: 'cyber-btn',
          style: { padding: '4px 12px', fontSize: '0.78em', minHeight: '44px' },
          onClick: () => viewReportContent(r.filename),
        }, 'عرض التقرير'),
      ]);
      container.appendChild(row);
    });
  } catch (err) {
    container.textContent = '';
    container.appendChild(uiEl('div', { style: { color: 'var(--rose)' } }, `خطأ أثناء تحميل التقارير: ${err}`));
  }
}

async function viewReportContent(filename) {
  try {
    const res = await fetch(`/api/enhanced/reports/${encodeURIComponent(filename)}`);
    const text = await res.text();
    const card = document.getElementById('report-viewer-card');
    if (card) card.style.display = 'block';
    const titleEl = document.getElementById('viewer-report-title');
    if (titleEl) titleEl.textContent = filename;
    const bodyEl = document.getElementById('viewer-report-body');
    if (bodyEl) bodyEl.textContent = text;
    if (card) card.scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    showUiNotice('فشل قراءة ملف التقرير: ' + err, 'error');
  }
}

async function loadSnapshotsList() {
  const container = document.getElementById('snapshots-sidebar-list');
  if (!container) return;
  try {
    const res = await fetch('/api/enhanced/snapshots');
    const data = await res.json();
    const snaps = data.snapshots || [];
    container.textContent = '';
    if (snaps.length === 0) {
      container.appendChild(uiEl('span', { style: { fontSize: '0.72em', color: 'var(--text-dim)' } }, 'لا توجد نقاط محفوظة.'));
      return;
    }
    snaps.forEach((s) => {
      container.appendChild(uiEl('button', {
        type: 'button',
        class: 'model-pill',
        style: { cursor: 'pointer', minHeight: '44px', border: '1px solid var(--border)', background: 'transparent' },
        onClick: () => selectResumeSnapshot(s.snapshot_id),
      }, [
        uiEl('span', { class: 'dot-status online' }),
        uiEl('span', { class: 'ltr-isolate', style: { fontSize: '0.75em', color: 'var(--cyan)' } }, s.snapshot_id),
      ]));
    });
  } catch (_) {
    container.textContent = '';
    container.appendChild(uiEl('span', { style: { fontSize: '0.72em', color: 'var(--rose)' } }, 'خطأ تحميل النقاط.'));
  }
}

function selectResumeSnapshot(snapId) {
  const input = document.getElementById('omni-resume-input');
  if (input) {
    input.value = snapId;
    switchPillar('omni', document.querySelector('.pillar-tab-btn'));
    showUiNotice(`تم اختيار نقطة الاستئناف: ${snapId}`, 'success');
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
  document.querySelectorAll('#category-filter-bar .cat-pill-btn').forEach((b) => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderArsenalGrid();
}

function filterArsenalTools() {
  renderArsenalGrid();
}

function renderArsenalGrid() {
  const container = document.getElementById('arsenal-tools-container');
  if (!container) return;
  container.textContent = '';

  const q = (document.getElementById('arsenal-search-box')?.value || '').toLowerCase().trim();
  const filtered = allArsenalTools.filter((t) => {
    const matchCat = currentCategory === 'all' || String(t.category || '').toLowerCase() === currentCategory.toLowerCase();
    const matchQ = !q || String(t.name || '').toLowerCase().includes(q) || String(t.description || '').toLowerCase().includes(q);
    return matchCat && matchQ;
  });

  if (filtered.length === 0) {
    container.appendChild(uiEl('div', { style: { gridColumn: '1/-1', textAlign: 'center', padding: '30px', color: 'var(--text-dim)' } },
      'لا توجد أدوات مطابقة للبحث أو الفئة المحددة.'));
    return;
  }

  filtered.forEach((t) => {
    const riskCls = `risk-${String(t.risk_level || 'info').toLowerCase()}`;
    const instCls = t.installed ? 'installed-yes' : 'installed-no';
    const instText = t.installed ? '● مثبت' : '○ غير مثبت (apt)';
    const tile = uiEl('div', { class: 'tool-tile' }, [
      uiEl('div', null, [
        uiEl('div', { class: 'tool-tile-top' }, [
          uiEl('span', { class: 'tool-tile-name ltr-isolate' }, t.name || ''),
          uiEl('span', { class: `risk-tag ${riskCls}` }, t.risk_level || ''),
        ]),
        uiEl('div', { class: 'ltr-isolate', style: { fontSize: '0.72em', color: 'var(--cyan)', margin: '3px 0 6px 0', fontFamily: 'var(--font-mono)' } }, t.category || ''),
        uiEl('div', { class: 'tool-tile-desc' }, t.description || ''),
      ]),
      uiEl('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px', borderTop: '1px solid var(--border)', paddingTop: '8px' } }, [
        uiEl('span', { class: `install-badge ${instCls}` }, instText),
        uiEl('button', {
          type: 'button',
          class: 'cyber-btn',
          style: { padding: '4px 10px', fontSize: '0.75em', minHeight: '44px' },
          onClick: () => inspectTool(t.name),
        }, 'فحص وتشغيل'),
      ]),
    ]);
    container.appendChild(tile);
  });
}

async function inspectTool(toolName) {
  modalActiveTool = toolName;
  const modal = document.getElementById('tool-modal');
  if (modal) modal.style.display = 'flex';
  const titleEl = document.getElementById('modal-tool-title');
  if (titleEl) titleEl.textContent = toolName;

  try {
    const res = await fetch(`/api/arsenal/tool/${encodeURIComponent(toolName)}`);
    const data = await res.json();
    const spEl = document.getElementById('modal-sys-prompt');
    if (spEl) spEl.textContent = data.system_prompt || 'Standard Persona';
    const schemaEl = document.getElementById('modal-mcp-schema');
    if (schemaEl) schemaEl.textContent = JSON.stringify(data.mcp_schema || {}, null, 2);
  } catch (err) {
    console.error('Modal load error:', err);
  }
}

function closeToolModal(event) {
  if (event && event.target && event.target.className !== 'cyber-modal-overlay') return;
  const modal = document.getElementById('tool-modal');
  if (modal) modal.style.display = 'none';
}

async function executeModalTool() {
  if (!modalActiveTool) return;
  const target = document.getElementById('modal-exec-target')?.value.trim() || '';
  if (!target) {
    showUiNotice('يرجى تحديد الهدف!', 'warning');
    return;
  }
  const pre = document.getElementById('modal-exec-result');
  if (pre) {
    pre.style.display = 'block';
    pre.classList.add('ltr-isolate');
    pre.setAttribute('dir', 'ltr');
    pre.textContent = `[*] Running ${modalActiveTool} against ${target}...`;
  }

  try {
    const res = await fetch('/api/arsenal/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool: modalActiveTool, target: target, thinking: true }),
    });
    const data = await res.json();
    if (pre) pre.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    if (pre) pre.textContent = 'خطأ أثناء التشغيل: ' + err;
  }
}

// ── Reconnaissance & Intelligence Studio Extensions ─────────────────────────
async function fetchTargetDorks() {
  const domain = document.getElementById('dork-target-domain')?.value.trim() || '';
  if (!domain) {
    showUiNotice('يرجى إدخال اسم النطاق (Target Domain)!', 'warning');
    return;
  }
  const box = document.getElementById('dorks-results-box');
  const list = document.getElementById('dorks-items-list');
  if (box) box.style.display = 'block';
  if (list) {
    list.textContent = '';
    list.appendChild(uiEl('div', { style: { color: 'var(--cyan)', padding: '10px' } }, 'جاري توليد استعلامات GHDB و GitHub Dorks...'));
  }

  try {
    const res = await fetch(`/api/recon/dorks?domain=${encodeURIComponent(domain)}`);
    const data = await res.json();
    _activeDorksData = data;
    filterDorkCategory('all', null);
  } catch (err) {
    if (list) {
      list.textContent = '';
      list.appendChild(uiEl('div', { style: { color: 'var(--red)', padding: '10px' } }, `خطأ أثناء جلب استعلامات Dorks: ${err}`));
    }
  }
}

function filterDorkCategory(category, btn) {
  if (btn && btn.parentElement) {
    btn.parentElement.querySelectorAll('.cat-pill-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
  }
  if (!_activeDorksData) return;

  const list = document.getElementById('dorks-items-list');
  if (!list) return;
  list.textContent = '';

  let items = [];
  if (category === 'all') {
    for (const [catName, catItems] of Object.entries(_activeDorksData.google_dorks || {})) {
      items = items.concat(catItems.map((it) => ({ ...it, source: 'Google', cat: catName })));
    }
    items = items.concat((_activeDorksData.github_dorks || []).map((it) => ({
      dork: it.query,
      search_url: it.search_url,
      source: 'GitHub',
      cat: it.name,
    })));
  } else if (category === 'github') {
    items = (_activeDorksData.github_dorks || []).map((it) => ({
      dork: it.query,
      search_url: it.search_url,
      source: 'GitHub',
      cat: it.name,
    }));
  } else {
    items = ((_activeDorksData.google_dorks || {})[category] || []).map((it) => ({
      ...it,
      source: 'Google',
      cat: category,
    }));
  }

  if (items.length === 0) {
    list.appendChild(uiEl('div', { style: { color: 'var(--text-muted)', padding: '10px' } }, 'لا توجد استعلامات في هذا القسم.'));
    return;
  }

  items.forEach((it) => {
    const row = uiEl('div', {
      style: {
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '6px 8px',
        borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
        fontSize: '12px',
        gap: '10px',
      },
    }, [
      uiEl('div', { style: { flex: '1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, [
        uiEl('span', {
          style: {
            display: 'inline-block',
            padding: '1px 6px',
            borderRadius: '3px',
            fontSize: '10px',
            background: it.source === 'Google' ? '#1a73e8' : '#333',
            color: '#fff',
            marginLeft: '6px',
          },
        }, it.source),
        uiEl('code', { class: 'ltr-isolate', dir: 'ltr', style: { color: '#a8ff78' } }, it.dork || ''),
      ]),
      uiEl('a', {
        href: safeHref(it.search_url),
        target: '_blank',
        rel: 'noopener noreferrer',
        style: {
          color: 'var(--cyan)',
          textDecoration: 'none',
          fontWeight: 'bold',
          whiteSpace: 'nowrap',
          padding: '6px 10px',
          minHeight: '44px',
          display: 'inline-flex',
          alignItems: 'center',
          border: '1px solid var(--cyan)',
          borderRadius: '4px',
          fontSize: '11px',
        },
      }, 'فتح ↗'),
    ]);
    list.appendChild(row);
  });
}

async function runJSSecretMiner() {
  const content = document.getElementById('js-miner-content')?.value.trim() || '';
  if (!content) {
    showUiNotice('يرجى وضع كود جافاسكريبت أو رابط الملف!', 'warning');
    return;
  }
  const out = document.getElementById('js-miner-output');
  if (!out) return;
  out.style.display = 'block';
  out.textContent = '';
  out.appendChild(uiEl('div', { style: { color: 'var(--cyan)' } }, 'جاري فحص الكود وحساب الإنتروبيا (Shannon Entropy)...'));

  try {
    const res = await fetch('/api/recon/mine-js', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: content, source: 'web_studio' }),
    });
    const data = await res.json();
    out.textContent = '';

    out.appendChild(uiEl('div', { style: { fontWeight: 'bold', marginBottom: '8px', color: 'var(--cyan)' } },
      `النتائج: ${data.secrets_count || 0} سر مكتشف | ${data.endpoints_count || 0} نقطة نهاية`));

    if (data.secrets_count > 0 && Array.isArray(data.secrets)) {
      out.appendChild(uiEl('div', { style: { fontWeight: 'bold', color: '#ff5e62', marginTop: '6px' } }, 'الأسرار المكتشفة:'));
      data.secrets.forEach((s) => {
        out.appendChild(uiEl('div', { style: { padding: '4px 0', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' } }, [
          uiEl('span', { style: { color: 'var(--yellow)', fontWeight: 'bold' } }, `[${s.secret_type || 'secret'}] `),
          uiEl('code', { class: 'ltr-isolate', dir: 'ltr' }, s.masked_value || ''),
          uiEl('span', { style: { color: 'var(--cyan)', fontSize: '10px', marginRight: '8px' } },
            ` (Entropy: ${s.entropy} | Confidence: ${s.confidence})`),
        ]));
      });
    }

    if (data.endpoints_count > 0 && Array.isArray(data.endpoints)) {
      out.appendChild(uiEl('div', { style: { fontWeight: 'bold', color: 'var(--cyan)', marginTop: '10px' } }, 'المسارات ونقاط الـ Endpoints المخفية:'));
      data.endpoints.slice(0, 15).forEach((ep) => {
        out.appendChild(uiEl('div', { style: { color: '#a8ff78', padding: '2px 0' } }, [
          uiEl('code', { class: 'ltr-isolate', dir: 'ltr' }, String(ep)),
        ]));
      });
    }
  } catch (err) {
    out.textContent = '';
    out.appendChild(uiEl('div', { style: { color: 'var(--red)' } }, `خطأ أثناء الفحص: ${err}`));
  }
}

async function generate403Bypasses() {
  const url = document.getElementById('bypass-target-url')?.value.trim() || '';
  if (!url) {
    showUiNotice('يرجى إدخال الرابط المستهدف المحظور (403 URL)!', 'warning');
    return;
  }
  const container = document.getElementById('bypass-output-container');
  if (!container) return;
  container.style.display = 'block';
  container.textContent = '';
  container.appendChild(uiEl('div', { style: { color: 'var(--cyan)' } }, 'جاري توليد مصفوفة الهيدرات والمسارات...'));

  try {
    const res = await fetch(`/api/recon/403-bypasses?url=${encodeURIComponent(url)}`);
    const data = await res.json();
    container.textContent = '';

    container.appendChild(uiEl('div', { style: { fontWeight: 'bold', marginBottom: '6px', color: 'var(--cyan)' } },
      `تم توليد ${data.count || 0} محاولة تجاوز:`));

    (data.variations || []).forEach((v, idx) => {
      const headerStr = Object.entries(v.headers || {}).map(([k, val]) => `-H "${k}: ${val}"`).join(' ');
      const curlCmd = `curl -k -s -o /dev/null -w "%{http_code}" ${headerStr ? headerStr + ' ' : ''}"${v.url}"`;
      const row = uiEl('div', {
        style: {
          padding: '4px 0',
          borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '8px',
        },
      }, [
        uiEl('div', { style: { flex: '1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, [
          uiEl('span', { style: { color: 'var(--yellow)', fontSize: '11px' } }, `#${idx + 1} [${v.type}] `),
          uiEl('code', { class: 'ltr-isolate', dir: 'ltr', style: { color: '#fff', fontSize: '11px', marginRight: '6px' } }, v.description || ''),
        ]),
        uiEl('button', {
          type: 'button',
          class: 'cyber-btn',
          style: { padding: '4px 10px', fontSize: '11px', minHeight: '44px' },
          onClick: () => {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(curlCmd).then(() => showUiNotice('تم نسخ أمر cURL', 'success')).catch(() => {});
            }
          },
        }, 'نسخ cURL'),
      ]);
      container.appendChild(row);
    });
  } catch (err) {
    container.textContent = '';
    container.appendChild(uiEl('div', { style: { color: 'var(--red)' } }, `خطأ: ${err}`));
  }
}
