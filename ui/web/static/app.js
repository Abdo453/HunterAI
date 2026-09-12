'use strict';
let scanWs = null, chatWs = null, sid = null;
let currentTab = 'scan';

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadStatus();
  loadSessions();
  initChat();
  loadMethodology();
  checkBurpStatus();
  updateHintsCounter();
  checkAgentQuestions();
  setInterval(updateGPUStatus, 3000);
  setInterval(checkBurpStatus, 5000);
  setInterval(checkAgentQuestions, 4000);
  setInterval(updateHintsCounter, 5000);
});


function switchTab(tab, btn) {
  currentTab = tab;
  document.querySelectorAll('.tab, .tab-btn').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content, .view-panel').forEach(t => {
    t.classList.remove('active');
    t.style.display = 'none';
  });
  
  if(btn) btn.classList.add('active');
  const el = document.getElementById(`tab-${tab}`) || document.getElementById(`view-${tab}`);
  if(el) {
    el.classList.add('active');
    el.style.display = 'flex';
  }

  if(tab === 'skills') loadSkills();
  if(tab === 'learning') loadLearningData();
  if(tab === 'intelligence') loadIntelligenceHub();
  if(tab === 'methodology') loadMethodology();
  if(tab === 'graph') setTimeout(refreshGraph, 100);
}

function switchView(view, btn) {
  switchTab(view, btn);
}

// ── Status + GPU ──────────────────────────────────────────────
async function loadStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    renderModels(d.local_models || []);
    renderApiKeys(d.api_keys || {});
  } catch(e) {}
}

function renderModels(models) {
  const el = document.getElementById('models-list');
  const defs = [
    {k:'whiterabbitneo', l:'WhiteRabbitNeo'},
    {k:'xploiter',       l:'xploiter/pentester'},
    {k:'qwen2.5-coder',  l:'qwen2.5-coder:14b'},
  ];
  el.innerHTML = defs.map(m => {
    const on = models.some(x => x.toLowerCase().includes(m.k));
    return `<div class="msi">
      <div class="sd ${on?'son':'sof'}" id="dot-${m.k}"></div>
      <span style="color:${on?'#e0e0e0':'#555'};font-size:.76em">${m.l}</span>
    </div>`;
  }).join('');
}

function renderApiKeys(keys) {
  const el = document.getElementById('api-list');
  el.innerHTML = Object.entries(keys).map(([k,v]) =>
    `<div class="api-si"><div class="api-dot ${v?'api-on':'api-off'}"></div><span style="color:${v?'#aaa':'#555'}">${k}</span></div>`
  ).join('');
}

function updateGPUStatus() {
  // GPU status يتحدث من events الـ WebSocket
  // هنا فقط نتحقق من الـ loaded models
  fetch('/api/status').then(r=>r.json()).then(d=>{
    const loaded = d.loaded_models || [];
    const defs = {whiterabbitneo:'dot-whiterabbitneo', 'xploiter':'dot-xploiter', 'qwen2.5-coder':'dot-qwen2.5-coder'};
    Object.entries(defs).forEach(([k,id]) => {
      const dot = document.getElementById(id);
      if(!dot) return;
      const isLoaded = loaded.some(m => m.toLowerCase().includes(k));
      dot.className = `sd ${isLoaded ? 'sld' : d.local_models?.some(m=>m.toLowerCase().includes(k)) ? 'son' : 'sof'}`;
    });
  }).catch(()=>{});
}

function setGPUPanel(ev) {
  const gs = ev.gpu_status || {};
  const stEl = document.getElementById('gpu-state');
  const mdEl = document.getElementById('gpu-model');
  const quEl = document.getElementById('gpu-queue');
  const rnEl = document.getElementById('gpu-runs');

  if(stEl) {
    stEl.textContent = gs.locked ? 'BUSY' : 'FREE';
    stEl.className = `gpu-val ${gs.locked?'busy':'free'}`;
  }
  if(mdEl) mdEl.textContent = gs.current_model ? gs.current_model.split('/').pop().split(':')[0] : '—';
  if(quEl) quEl.textContent = gs.queue_length || 0;
  if(rnEl) rnEl.textContent = gs.total_runs || 0;
}

// ── CHAT ──────────────────────────────────────────────────────
function initChat() {
  chatWs = new WebSocket(`ws://${location.host}/ws/chat`);
  chatWs.onmessage = e => handleChatEvent(JSON.parse(e.data));
  chatWs.onclose = () => {
    document.getElementById('chat-btn').disabled = false;
    setTimeout(initChat, 2000); // auto-reconnect
  };
  chatWs.onerror = () => {};
}

function onModelChange() {
  const sel = document.getElementById('chat-model-select');
  const badge = document.getElementById('selected-model-badge');
  if(!sel || !badge) return;
  const val = sel.value;
  if(val === 'auto') {
    badge.textContent = 'Auto (Smart Router)';
    badge.className = 'model-badge mb-auto';
  } else if(val.startsWith('local:')) {
    const name = val.replace('local:','').split('/')[0].split(':')[0];
    badge.textContent = `💻 Local: ${name}`;
    badge.className = 'model-badge mb-local';
  } else if(val.startsWith('api:')) {
    const name = val.replace('api:','').split('/')[1] || val.replace('api:','');
    badge.textContent = `☁️ Cloud: ${name}`;
    badge.className = 'model-badge mb-api';
  }
}

function clearChat() {
  document.getElementById('chat-messages').innerHTML = '';
  if(chatWs && chatWs.readyState === WebSocket.OPEN) {
    chatWs.send(JSON.stringify({action: 'clear_memory'}));
  }
}

function sendChat() {
  const inp = document.getElementById('chat-input');
  const sel = document.getElementById('chat-model-select');
  const msg = inp ? inp.value.trim() : '';
  const selectedModel = sel ? sel.value : 'auto';
  if(!msg || !chatWs || chatWs.readyState !== WebSocket.OPEN) return;

  addChatMsg('user', msg);
  if(inp) inp.value = '';
  const chatBtn = document.getElementById('chat-btn');
  if(chatBtn) chatBtn.disabled = true;

  const routePanel = document.getElementById('route-panel');
  if(routePanel) routePanel.classList.remove('hidden');
  const routeBadge = document.getElementById('route-badge');
  if(routeBadge) {
    routeBadge.textContent = selectedModel === 'auto' ? 'ROUTING...' : 'MANUAL';
    routeBadge.className = 'rbadge rb-rtn';
  }
  const routeFlow = document.getElementById('route-flow');
  if(routeFlow) routeFlow.innerHTML = '<span class="rf-step active">Preparing model execution...</span>';

  // Add thinking placeholder
  const chatMessages = document.getElementById('chat-messages');
  if(chatMessages) {
    const typingDiv = document.createElement('div');
    typingDiv.id = 'typing-indicator';
    typingDiv.className = 'msg ai';
    typingDiv.innerHTML = `<div class="mb" style="color:#aaa;font-style:italic">⏳ جاري إرسال الطلب للموديل المحدد...</div>`;
    chatMessages.appendChild(typingDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  chatWs.send(JSON.stringify({message: msg, model: selectedModel}));
}

function handleChatEvent(d) {
  const ev = d.event;

  if(ev === 'task_classified') {
    const t = d.task_type;
    const cls = {SECURITY:'rb-sec',CODING:'rb-cod',MIXED:'rb-mix',GENERAL:'rb-gen'}[t] || 'rb-rtn';
    const routeBadge = document.getElementById('route-badge');
    if(routeBadge) {
      routeBadge.textContent = t;
      routeBadge.className = `rbadge ${cls}`;
    }
    const routeReason = document.getElementById('route-reason');
    if(routeReason) routeReason.textContent = d.reasoning || '';
    renderRouteFlow(t, d.models || []);

    const typing = document.getElementById('typing-indicator');
    if(typing) {
      const mb = typing.querySelector('.mb');
      if(mb) mb.innerHTML = `⚙️ <strong>[${t}]</strong> تم اختيار: ${d.models ? d.models.join(', ') : 'AI Model'} — جاري التوليد على الـ GPU...`;
    }
  }
  else if(ev === 'gpu_queued') {
    updateFlowStep(d.model, 'queued');
  }
  else if(ev === 'gpu_active') {
    updateFlowStep(d.model, 'active');
    setGPUPanel({gpu_status: {locked:true, current_model:d.model, queue_length:d.queue||0}});
    const typing = document.getElementById('typing-indicator');
    if(typing) {
      const mb = typing.querySelector('.mb');
      if(mb) mb.innerHTML = `🧠 <strong>${d.model}</strong> نشط الآن على الـ GPU ويقوم بالتوليد...`;
    }
  }
  else if(ev === 'gpu_done') {
    updateFlowStep(d.model, 'done');
    setGPUPanel({gpu_status: {locked:false, current_model:null}});
  }
  else if(ev === 'uncertainty_detected') {
    log('w', `[!] UNCERTAINTY DETECTED: "${d.pattern}" — triggering Confidence Check Protocol`);
    log('w', `    Launching ALL API models in parallel for verification...`);
    addChatMsg('ai',
      `🔍 Uncertainty detected in model response.\n` +
      `Activating Confidence Check Protocol:\n` +
      `→ GPT-4o, Claude 3.5, Gemini, Llama 70B, Mistral all verifying simultaneously...\n` +
      `→ BurpSuite/Browser verification: ${d.target || 'target'}`,
      'CONFIDENCE CHECK', 0
    );
  }
  else if(ev === 'confidence_check_start') {
    log('c', `[CONFIDENCE] Checking: ${d.claim?.substring(0,60)}... | ${d.models} models + browser`);
  }
  else if(ev === 'confidence_phase') {
    log('i', `[CONFIDENCE] Phase ${d.phase}: ${d.message}`);
  }
  else if(ev === 'model_verdict') {
    const icon = d.verdict==='CONFIRMED'?'✓':d.verdict==='FALSE_POSITIVE'?'✗':'?';
    log(d.verdict==='CONFIRMED'?'s':d.verdict==='FALSE_POSITIVE'?'e':'w',
      `  [${icon}] ${d.model}: ${d.verdict} (${Math.round(d.confidence*100)}%) — ${d.time}s`);
  }
  else if(ev === 'confidence_result') {
    const em = d.verdict==='CONFIRMED'?'🔴':d.verdict==='FALSE_POSITIVE'?'🟢':'🟡';
    log('s', `[CONFIDENCE RESULT] ${em} ${d.verdict} | Score: ${Math.round(d.score*100)}% | ${d.agreed} confirmed / ${d.disagreed} false positive`);
  }
  else if(ev === 'browser_start') {
    log('c', `[BROWSER] Opening browser to verify: ${d.target}`);
  }
  else if(ev === 'proxy_active') {
    log('s', `[PROXY] ${d.proxy} active at ${d.addr}`);
  }
  else if(ev === 'chat_token') {
    const typing = document.getElementById('typing-indicator');
    if(typing) typing.remove();

    let streamMsg = document.getElementById('current-streaming-msg');
    if(!streamMsg) {
      const chatMessages = document.getElementById('chat-messages');
      streamMsg = document.createElement('div');
      streamMsg.id = 'current-streaming-msg';
      streamMsg.className = 'msg ai';
      streamMsg.innerHTML = `<div class="mb"></div>`;
      chatMessages.appendChild(streamMsg);
    }
    const mb = streamMsg.querySelector('.mb');
    mb.textContent += d.token;
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
  else if(ev === 'chat_response') {
    const typing = document.getElementById('typing-indicator');
    if(typing) typing.remove();

    const streamMsg = document.getElementById('current-streaming-msg');
    if(streamMsg) {
      streamMsg.removeAttribute('id');
      const mb = streamMsg.querySelector('.mb');
      mb.innerHTML = escHtml(d.answer);
      const meta = document.createElement('div');
      meta.className = 'msg-meta';
      meta.textContent = `${d.route || ''} ${d.duration ? `· ${d.duration}s` : ''}`;
      streamMsg.appendChild(meta);
    } else {
      addChatMsg('ai', d.answer, d.route, d.duration);
    }

    const chatBtn = document.getElementById('chat-btn');
    if(chatBtn) chatBtn.disabled = false;
    if(d.gpu_status) setGPUPanel({gpu_status: d.gpu_status});
  }
  else if(ev === 'step') {
    updateFlowStep(d.model || d.action, 'active');
  }
  else if(ev === 'step_done') {
    updateFlowStep(d.model || '', 'done');
  }
  else if(ev === 'error') {
    const typing = document.getElementById('typing-indicator');
    if(typing) typing.remove();

    addChatMsg('ai', `Error: ${d.message}`, 'ERROR', 0);
    const chatBtn = document.getElementById('chat-btn');
    if(chatBtn) chatBtn.disabled = false;
  }
}

function addChatMsg(role, content, route, duration) {
  const el = document.getElementById('chat-messages');
  const splitEl = document.getElementById('split-chat-messages');
  const meta = (route || duration) ? `<div class="msg-meta" style="font-size:0.75em;color:#7d8590;margin-top:4px;">${route||''} ${duration?`· ${duration}s`:''}</div>` : '';
  const html = `
    <div class="msg ${role}">
      <div class="mb">${escHtml(content)}</div>
      ${meta}
    </div>
  `;
  if(el) { el.innerHTML += html; el.scrollTop = el.scrollHeight; }
  if(splitEl) { splitEl.innerHTML += html; splitEl.scrollTop = splitEl.scrollHeight; }
}


function renderRouteFlow(taskType, models) {
  const flow = document.getElementById('route-flow');
  if(!flow) return;
  const targetModel = (models && models.length) ? (models[0].split('/').pop().split(':')[0]) : 'Selected Model';
  const steps = {
    MANUAL: [
      {l: targetModel, t: 'local'},
      {l: '→', t: 'arrow'},
      {l: 'Local GPU', t: 'local'},
      {l: '→', t: 'arrow'},
      {l: 'Result', t: 'done'},
    ],
    MANUAL_API: [
      {l: targetModel, t: 'api'},
      {l: '→', t: 'arrow'},
      {l: 'Cloud API (No GPU)', t: 'api'},
      {l: '→', t: 'arrow'},
      {l: 'Result', t: 'done'},
    ],
    SECURITY: [
      {l:'WhiteRabbitNeo', t:'local'},
      {l:'→', t:'arrow'},
      {l:'GPU FREE', t:'arrow'},
      {l:'→', t:'arrow'},
      {l:'Xploiter', t:'local'},
      {l:'→', t:'arrow'},
      {l:'Merge', t:'done'},
    ],
    CODING: [
      {l:'Qwen 14B', t:'local'},
      {l:'→', t:'arrow'},
      {l:'Security?', t:'check'},
      {l:'→', t:'arrow'},
      {l:'API (if needed)', t:'api'},
      {l:'→', t:'arrow'},
      {l:'Result', t:'done'},
    ],
    MIXED: [
      {l:'Security API', t:'api'},
      {l:'‖', t:'arrow'},
      {l:'Qwen 14B', t:'local'},
      {l:'→', t:'arrow'},
      {l:'Integrate', t:'done'},
    ],
    GENERAL: [{l:'Qwen 14B', t:'local'}, {l:'→', t:'arrow'}, {l:'Result', t:'done'}]
  };
  const s = steps[taskType] || steps.GENERAL;
  flow.innerHTML = s.map(st => {
    if(st.t==='arrow') return `<span class="rf-arrow">${st.l}</span>`;
    const cls = st.t==='local'?'rf-step':st.t==='api'?'rf-step api':st.t==='done'?'rf-step done':'rf-step';
    return `<span class="${cls}" data-model="${st.l}">${st.l}</span>`;
  }).join('');
}

function updateFlowStep(modelName, state) {
  document.querySelectorAll('.rf-step').forEach(el => {
    const lbl = el.dataset.model || '';
    if(!modelName) return;
    if(modelName.toLowerCase().includes(lbl.toLowerCase()) ||
       lbl.toLowerCase().includes(modelName.toLowerCase().split('/').pop().split(':')[0])) {
      el.className = state==='active' ? 'rf-step active' : state==='done' ? 'rf-step done' : 'rf-step';
    }
  });
}

function escHtml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
}

// ── SCAN ──────────────────────────────────────────────────────
function getTargetUrl() {
  const el = document.getElementById('target-inp') || document.getElementById('target');
  return el ? el.value.trim() : '';
}

async function checkBurpStatus() {
  try {
    const r = await fetch('/api/diagnostics/preflight');
    const d = await r.json();
    const badges = [document.getElementById('burp-live-badge'), document.getElementById('split-burp-badge')];
    if (d && d.burp) {
      badges.forEach(b => {
        if(!b) return;
        if (d.burp.online) {
          b.className = 'burp-badge online';
          b.textContent = '🟢 Burp متصل (127.0.0.1:8080)';
        } else {
          b.className = 'burp-badge offline';
          b.textContent = '🔴 Burp غير متصل';
        }
      });
    }
    return d;
  } catch(e) {
    return null;
  }
}

function onBurpToggleChange() {
  const chk = document.getElementById('use-proxy-chk');
  if (chk && chk.checked) {
    checkBurpStatus();
  }
}

// ── Agent Co-Pilot: User Advice & Hints ──────────────────────
async function sendAsAgentHint(customText) {
  const inp = document.getElementById('chat-input');
  const text = customText || (inp ? inp.value.trim() : '');
  if (!text) return;

  try {
    const r = await fetch('/api/agent/hint', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({hint: text, category: 'user_guidance'})
    });
    const d = await r.json();
    
    addChatMsg('user user-hint', text, 'ADVICE TO AGENT');
    addChatMsg('ai', `💡 استلمت توجيهك باهتمام: "${text}". تم تسجيله وإدراجه فوراً في خطة الفحص والاستدلال!`, 'AGENT CO-PILOT');
    
    if (inp && !customText) inp.value = '';
    updateHintsCounter();
  } catch(e) {
    console.error('Failed to post hint:', e);
  }
}

function sendQuickHint(hintText) {
  sendAsAgentHint(hintText);
}

async function updateHintsCounter() {
  try {
    const r = await fetch('/api/agent/hints');
    const d = await r.json();
    const counter = document.getElementById('active-hints-counter');
    if (counter) counter.textContent = `${d.total || 0} نصيحة`;
  } catch(e) {}
}

// ── Agent Interactive Questions (Human-in-the-Loop) ──────────
async function checkAgentQuestions() {
  try {
    const r = await fetch('/api/agent/questions');
    const d = await r.json();
    const pending = d.pending_questions || [];
    const banners = [
      {box: document.getElementById('agent-question-banner'), txt: document.getElementById('aq-text'), btns: document.getElementById('aq-buttons')},
      {box: document.getElementById('split-question-banner'), txt: document.getElementById('split-aq-text'), btns: document.getElementById('split-aq-buttons')}
    ];

    if (pending.length > 0) {
      const q = pending[0];
      banners.forEach(b => {
        if (!b.box) return;
        b.box.style.display = 'block';
        if (b.txt) b.txt.textContent = q.question;
        if (b.btns) {
          b.btns.innerHTML = (q.options || ['نعم، وافق وتابع', 'تخطى هذا المسار']).map((opt, i) => {
            const cls = i === 0 ? 'yes' : i === 1 ? 'no' : 'custom';
            return `<button class="btn-q ${cls}" onclick="answerAgentQuestion('${q.id}', '${opt}')">${opt}</button>`;
          }).join('');
        }
      });
    } else {
      banners.forEach(b => {
        if (b.box) b.box.style.display = 'none';
      });
    }
  } catch(e) {}
}

async function answerAgentQuestion(qId, answer) {
  try {
    await fetch('/api/agent/answer', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({question_id: qId, answer: answer})
    });
    addChatMsg('user', `إجابتي على استشارة الـ Agent: ${answer}`, 'USER DECISION');
    checkAgentQuestions();
  } catch(e) {}
}

// ── Split View Handlers ─────────────────────────────────────
function sendSplitChat() {
  const inp = document.getElementById('split-chat-input');
  if (!inp) return;
  const msg = inp.value.trim();
  if (!msg) return;
  const mainInp = document.getElementById('chat-input');
  if (mainInp) mainInp.value = msg;
  sendChat();
  inp.value = '';
}

function sendSplitHint() {
  const inp = document.getElementById('split-chat-input');
  if (!inp) return;
  const msg = inp.value.trim();
  if (!msg) return;
  sendAsAgentHint(msg);
  inp.value = '';
}


async function startScan() {
  const target = getTargetUrl();
  if (!target) { alert('يرجى إدخال رابط أو نطاق الهدف أولاً!'); return; }

  const useProxyChk = document.getElementById('use-proxy-chk');
  let useProxyVal = useProxyChk ? useProxyChk.checked : false;

  // Pre-flight check for Burp Suite
  if (useProxyVal) {
    const diag = await checkBurpStatus();
    if (diag && diag.burp && !diag.burp.online) {
      const cont = confirm(
        "⚠️ تنبيه فحص البروكسي (Burp Suite Pre-flight Check):\n\n" +
        "لقد قمت بتفعيل خيار البروكسي، ولكن برنامج Burp Suite غير مفتوح حالياً على المنفذ (127.0.0.1:8080)!\n\n" +
        "- اضغط (موافق / OK) للمتابعة بالفحص المباشر بدون بروكسي.\n" +
        "- اضغط (إلغاء / Cancel) لإيقاف الفحص حتى تقوم بتشغيل Burp Suite أولاً."
      );
      if (!cont) {
        return;
      }
      if (useProxyChk) useProxyChk.checked = false;
      useProxyVal = false;
    }
  }

  sid = null;

  ['council-panel','output-panel','results-panel'].forEach(id => {
    const el = document.getElementById(id);
    if(el) el.style.display = 'block';
  });

  const repBtns = document.getElementById('report-btns');
  if(repBtns) repBtns.style.display = 'none';

  const findList = document.getElementById('findings-list');
  if(findList) findList.innerHTML = '';

  const sevSum = document.getElementById('sev-summary');
  if(sevSum) sevSum.innerHTML = '';

  const term = document.getElementById('terminal');
  if(term) term.innerHTML = '';

  const startBtn = document.getElementById('start-btn');
  if(startBtn) startBtn.disabled = true;

  ['wrn','xpl','qwen'].forEach(id => {
    const st = document.getElementById(`st-${id}`);
    const out = document.getElementById(`out-${id}`);
    if(st) { st.textContent='Waiting'; st.className='mc-status'; }
    if(out) { out.textContent=''; out.className='mc-out'; }
    const card = document.getElementById(`mc-${id}`);
    if(card) card.className='mc-card';
  });

  const modeVal = (document.getElementById('mode-sel') || document.getElementById('mode') || {}).value || 'bugbounty_full';
  const useBrowserVal = !!(document.getElementById('use-browser-chk') || document.getElementById('browser') || {}).checked;
  const authUser = (document.getElementById('auth-user-inp') || {}).value || '';
  const authPass = (document.getElementById('auth-pass-inp') || {}).value || '';
  const authCookie = (document.getElementById('auth-cookie-inp') || {}).value || '';
  const authLoginUrl = (document.getElementById('auth-login-url-inp') || {}).value || '';

  if(scanWs) scanWs.close();
  scanWs = new WebSocket(`ws://${location.host}/ws/scan`);
  scanWs.onopen = () => {
    scanWs.send(JSON.stringify({
      target: target,
      mode: modeVal,
      use_browser: useBrowserVal,
      use_proxy: useProxyVal,
      burp_proxy: '127.0.0.1:8080',
      auth: {
        username: authUser.trim(),
        password: authPass.trim(),
        cookie: authCookie.trim(),
        login_url: authLoginUrl.trim()
      }
    }));
    log('i', `[*] Target: ${target} | Proxy: ${useProxyVal ? '127.0.0.1:8080 (Burp Suite)' : 'Direct'}${authUser || authCookie ? ' | 🔐 Auth Configured' : ''}`);
  };
  scanWs.onmessage = e => handleScanEvent(JSON.parse(e.data));
  scanWs.onclose = () => {
    const btn = document.getElementById('start-btn');
    if(btn) btn.disabled = false;
    loadSessions();
  };
}

function handleScanEvent(d) {
  const ev = d.event;
  if(ev==='session_created') { sid=d.session_id; log('i',`[SESSION] ${d.session_id}`); }
  else if(ev==='gpu_active') {
    const mn=(d.model||'').toLowerCase();
    const id=mn.includes('whiterabbit')?'wrn':mn.includes('xploiter')?'xpl':mn.includes('qwen')?'qwen':null;
    if(id) {
      const st=document.getElementById(`st-${id}`); const card=document.getElementById(`mc-${id}`);
      if(st){st.textContent='RUNNING';st.className='mc-status act';}
      if(card) card.className='mc-card active';
    }
    log('c',`[GPU] Active: ${d.model}`);
    setGPUPanel({gpu_status:{locked:true,current_model:d.model}});
  }
  else if(ev==='gpu_done') {
    const mn=(d.model||'').toLowerCase();
    const id=mn.includes('whiterabbit')?'wrn':mn.includes('xploiter')?'xpl':mn.includes('qwen')?'qwen':null;
    if(id) {
      const st=document.getElementById(`st-${id}`); const card=document.getElementById(`mc-${id}`);
      const out=document.getElementById(`out-${id}`);
      if(st){st.textContent='DONE';st.className='mc-status dn';}
      if(card) card.className='mc-card done';
    }
    log('g',`[GPU] Freed: ${d.model}`);
    setGPUPanel({gpu_status:{locked:false,current_model:null}});
  }
  else if(ev==='step_done') {
    const mn=(d.model||'').toLowerCase();
    const id=mn.includes('whiterabbit')?'wrn':mn.includes('xploiter')?'xpl':mn.includes('qwen')?'qwen':null;
    if(id) { const out=document.getElementById(`out-${id}`); if(out&&d.chars){out.textContent=`Done (${d.chars} chars)`;out.className='mc-out act';} }
  }
  else if(ev==='api_start') {
    (d.models||[]).forEach(m => {
      log('c', `[CLOUD AI] استدعاء الموديل السحابي: ${m}`);
    });
  }
  else if(ev==='api_model_active') {
    const key = d.key;
    const st = document.getElementById(`st-${key}`);
    if(st) { st.textContent = 'RUNNING'; st.style.color = '#00ff41'; }
    const out = document.getElementById(`out-${key}`);
    if(out) { out.textContent = 'جاري التحليل الأمني المتقدم للهدف...'; }
  }
  else if(ev==='api_response') {
    const key = d.key;
    const st = document.getElementById(`st-${key}`);
    if(st) { st.textContent = 'DONE'; st.style.color = '#00e5ff'; }
    const out = document.getElementById(`out-${key}`);
    if(out) { out.textContent = d.summary || 'اكتمل التحليل بنجاح.'; }
    log('s', `[CLOUD AI ✓] استلمنا تقييم أمني ذكي من: ${d.api}`);
  }
  else if(ev==='api_model_error') {
    const key = d.key;
    const st = document.getElementById(`st-${key}`);
    if(st) { st.textContent = 'OFFLINE'; st.style.color = '#ff2a4b'; }
  }
  else if(ev==='log') {
    const msg = d.message || '';
    if(msg.includes('[EXEC]')) log('c', msg);
    else if(msg.includes('[PROBING') || msg.includes('Testing')) log('w', msg);
    else if(msg.includes('[CONFIRMED')) log('e', msg);
    else if(msg.includes('[SQLMAP') || msg.includes('[NUCLEI') || msg.includes('[DALFOX') || msg.includes('[FOUND]')) log('i', msg);
    else log('t', msg);
  }
  else if(ev==='phase') log('i',`[PHASE] ${d.message||''}`);
  else if(ev==='agent_start') log('a',`[AGENT] ${d.agent} started`);
  else if(ev==='agent_done') log('s',`[AGENT] ${d.agent} → ${d.findings} findings`);
  else if(ev==='tool_start') log('t',`  |-- ${d.tool}`);
  else if(ev==='tool_done') log('t',`  L-- ${d.tool}: done`);
  else if(ev==='scan_complete'||ev==='done') {
    sid=d.session_id||sid;
    log('s',`\n[DONE] Findings: ${d.total_findings||0} | Critical: ${d.critical||0} | High: ${d.high||0}`);
    if(sid) loadSession(sid);
    document.getElementById('report-btns').classList.remove('hidden');
    if(scanWs) scanWs.close();
  }
  else if(ev==='error') log('e',`[ERROR] ${d.message||''}`);
}

async function loadSession(id) {
  if(!id) return; sid=id;
  try {
    switchTab('scan', document.querySelector("button[onclick*='scan']"));
    const r=await fetch(`/api/session/${id}`); const d=await r.json();
    const counts={Critical:0,High:0,Medium:0,Low:0,Info:0};
    (d.findings||[]).forEach(f=>{counts[f.severity]=(counts[f.severity]||0)+1;});
    const cc={'Critical':'scrit','High':'shigh','Medium':'smed','Low':'slow','Info':'sinf'};
    document.getElementById('sev-summary').innerHTML=Object.entries(counts).filter(([,v])=>v>0)
      .map(([k,v])=>`<div class="sc ${cc[k]}">${k}<br><strong>${v}</strong></div>`).join('');
    document.getElementById('findings-list').innerHTML=(d.findings||[]).map((f,i)=>`
      <div class="fc"><div class="fch fc${f.severity[0].toLowerCase()}" onclick="tf(${i})">
        <span class="fb" style="${ss(f.severity)}">${f.severity}</span>
        <span class="fcv">CVSS ${f.cvss||'?'}</span>
        <span class="ft">${f.title}</span>
        <span class="ftl">${f.tool}</span>
      </div><div class="fbd" id="fb${i}"><pre>${(f.evidence||'').substring(0,400)}</pre></div></div>`).join('');
    document.getElementById('results-panel').classList.remove('hidden');
    if(d.findings&&d.findings.length) document.getElementById('report-btns').classList.remove('hidden');
  } catch(e) {}
}

async function loadSessions() {
  try {
    const r=await fetch('/api/sessions'); const data=await r.json();
    const el=document.getElementById('sessions-list');
    if(!el) return;
    if(!data.length){el.innerHTML='<div style="padding:8px;color:#555;font-size:.72em">لا توجد جلسات سابقة</div>';return;}
    el.innerHTML=data.slice(0,10).map(s=>`
      <div class="si" onclick="loadSession('${s.id}')" style="background:#080c13;border:1px solid #1c2638;border-radius:6px;padding:8px 10px;margin-bottom:6px;cursor:pointer;transition:0.2s;" onmouseover="this.style.borderColor='#3399ff'" onmouseout="this.style.borderColor='#1c2638'">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;gap:6px;">
          <strong style="color:#fff;font-size:0.82em;direction:ltr;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:140px;">${s.target}</strong>
          <span style="font-size:0.68em;padding:2px 6px;border-radius:3px;font-weight:bold;${s.status==='completed'?'background:#003311;color:#00ff41;border:1px solid #00aa33':'background:#332200;color:#ffaa00;border:1px solid #aa8800'}">${s.status==='completed'?'مكتمل ✅':'قيد الفحص ⏳'}</span>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:0.72em;color:#888;">
          <span style="color:#3399ff;">${s.mode}</span>
          <span style="color:#00ff41;font-weight:bold;">${s.findings_count} نتائج</span>
        </div>
      </div>`).join('');
  } catch(e) {}
}

function tf(i){const e=document.getElementById(`fb${i}`);e.style.display=e.style.display==='block'?'none':'block';}
function ss(s){const m={Critical:'background:#330000;color:#ff3333',High:'background:#2a1500;color:#ff6600',Medium:'background:#2a2000;color:#ffaa00',Low:'background:#002200;color:#00aa00',Info:'background:#001533;color:#3399ff'};return m[s]||'';}
function dl(fmt){if(!sid)return;window.open(`/api/report/${sid}/${fmt}`,'_blank');}
function exportReport(fmt){ dl(fmt); }
function log(type, msg) {
  const t = document.getElementById('terminal');
  const splitT = document.getElementById('split-terminal');
  const m = {i:'li', t:'lt', w:'lw', e:'le', s:'ls', c:'lc', a:'la', g:'lg'};
  const cls = m[type] || 'li';
  if (t) {
    const d = document.createElement('div');
    d.className = cls;
    d.textContent = msg;
    t.appendChild(d);
    t.scrollTop = t.scrollHeight;
  }
  if (splitT) {
    const d2 = document.createElement('div');
    d2.className = cls;
    d2.textContent = msg;
    splitT.appendChild(d2);
    splitT.scrollTop = splitT.scrollHeight;
  }
}

function clearLog() {
  const t = document.getElementById('terminal');
  if (t) t.innerHTML = '';
  const splitT = document.getElementById('split-terminal');
  if (splitT) splitT.innerHTML = '';
}


async function runQuickTool(toolType) {
  const target = getTargetUrl();
  if(!target) {
    alert('Please enter a Target in the Scan tab first!');
    return;
  }
  
  const outEl = document.getElementById('output-panel');
  if(outEl) outEl.style.display = 'block';
  log('i', `\n[TOOL EXEC] Target: ${target} | Action: ${toolType.toUpperCase()}`);

  if(toolType === 'waf') {
    log('c', `[*] Probing target headers and signatures for WAF & Rate Limiting...`);
    try {
      const r = await fetch('/api/waf-check', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
      });
      const d = await r.json();
      if(d.waf_detected) {
        log('e', `[!] WAF DETECTED: ${d.waf_names.join(', ')} (Confidence: ${Math.round(d.confidence*100)}%)`);
        log('w', `[*] Recommended Scan Profile: ${d.recommended_mode} | Dynamic Delay: ${d.delay_range[0]}-${d.delay_range[1]}s`);
      } else {
        log('s', `[+] No WAF detected! Target is open for standard / fast scanning.`);
      }
    } catch(err) {
      log('e', `[!] WAF Check Error: ${err}`);
    }
  } else {
    let toolName = toolType;
    let toolArgs = '';
    if(toolType === 'nmap') {
      toolName = 'nmap';
      toolArgs = '-F --open';
    } else if(toolType === 'httpx') {
      toolName = 'httpx';
      toolArgs = '';
    } else if(toolType === 'wafw00f') {
      toolName = 'wafw00f';
    }

    log('c', `[*] Executing: ${toolName} ${target} ${toolArgs}...`);
    try {
      const r = await fetch('/api/run-tool', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({tool: toolName, target: target, args: toolArgs})
      });
      const d = await r.json();
      log(d.success ? 's' : 'w', `[COMPLETED] ${toolName} finished in ${d.duration}s`);
      if(d.stdout) {
        log('t', d.stdout);
      }
      if(d.stderr) {
        log('w', d.stderr);
      }
    } catch(err) {
      log('e', `[!] Execution Error: ${err}`);
    }
  }
}

// ── Methodology Knowledge Base ────────────────────────────────
let methodologyData = null;

async function loadMethodology() {
  const container = document.getElementById('methodology-container');
  if(!container) return;
  try {
    const r = await fetch('/api/methodology');
    methodologyData = await r.json();
    renderMethodology(methodologyData.steps);
  } catch(e) {
    container.innerHTML = '<div style="color:red">Error loading methodology playbooks.</div>';
  }
}

function renderMethodology(steps) {
  const container = document.getElementById('methodology-container');
  if(!container || !steps) return;
  let html = '';
  for(const [stepTitle, tools] of Object.entries(steps)) {
    html += `<div class="card" style="background:#111;border:1px solid #222;border-radius:6px;padding:12px;">
      <h3 style="color:#ff3333;margin:0 0 10px 0;font-size:14px;">${escHtml(stepTitle)}</h3>
      <div style="display:flex;flex-direction:column;gap:8px;">`;
    for(const t of tools) {
      const cmd = t.cmd || t.command || '';
      html += `<div style="background:#181818;border:1px solid #282828;border-radius:5px;padding:8px 10px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
          <strong style="color:#00ff41;font-size:13px;">${escHtml(t.tool)}</strong>
          <span style="color:#888;font-size:11px;">${escHtml(t.desc)}</span>
        </div>
        <pre style="margin:0;background:#050505;color:#e0e0e0;padding:6px 8px;border-radius:4px;font-size:12px;overflow-x:auto;"><code>${escHtml(cmd)}</code></pre>
      </div>`;
    }
    html += `</div></div>`;
  }
  container.innerHTML = html;
}

function searchMethodology(q) {
  if(!methodologyData || !methodologyData.steps) return;
  if(!q || !q.trim()) {
    renderMethodology(methodologyData.steps);
    return;
  }
  const query = q.toLowerCase();
  const filtered = {};
  for(const [stepTitle, tools] of Object.entries(methodologyData.steps)) {
    const matches = tools.filter(t => 
      t.tool.toLowerCase().includes(query) || 
      (t.cmd||t.command||'').toLowerCase().includes(query) || 
      (t.desc||'').toLowerCase().includes(query) ||
      stepTitle.toLowerCase().includes(query)
    );
    if(matches.length > 0) {
      filtered[stepTitle] = matches;
    }
  }
  renderMethodology(filtered);
}

// ── Visual Attack Surface Graph (Vis.js) ──────────────────────
let networkGraph = null;
let graphNodes = null;
let graphEdges = null;

function initGraph() {
  const container = document.getElementById('network-graph');
  if(!container || networkGraph) return;

  graphNodes = new vis.DataSet([]);
  graphEdges = new vis.DataSet([]);

  const data = { nodes: graphNodes, edges: graphEdges };
  const options = {
    nodes: {
      shape: 'box',
      margin: 10,
      font: { color: '#ffffff', face: 'monospace', size: 12 },
      borderWidth: 2,
      shadow: true
    },
    edges: {
      color: { color: '#444444', highlight: '#00ff41' },
      arrows: { to: { enabled: true, scaleFactor: 0.6 } },
      font: { color: '#888888', size: 10, align: 'top' },
      smooth: { type: 'cubicBezier' }
    },
    groups: {
      target: { color: { background: '#003366', border: '#00ccff' }, shape: 'ellipse', font: { size: 14, bold: true } },
      subdomain: { color: { background: '#002244', border: '#0099cc' } },
      web: { color: { background: '#002b11', border: '#00ff41' } },
      waf: { color: { background: '#332200', border: '#ffaa00' }, shape: 'diamond' },
      endpoint: { color: { background: '#220033', border: '#cc66ff' } },
      vuln: { color: { background: '#440000', border: '#ff3333' }, shape: 'circle' }
    },
    physics: {
      stabilization: false,
      barnesHut: { gravitationalConstant: -3000, springConstant: 0.04, springLength: 95 }
    }
  };

  networkGraph = new vis.Network(container, data, options);
}

async function refreshGraph() {
  initGraph();
  try {
    const r = await fetch('/api/pipeline/graph');
    const d = await r.json();
    if(d && d.nodes) {
      updateGraphData(d.nodes, d.edges || []);
    }
  } catch(err) {
    console.error('Error refreshing graph:', err);
  }
}

function resetGraphView() {
  if(networkGraph) networkGraph.fit({ animation: true });
}

function updateGraphData(nodesList, edgesList) {
  if(!graphNodes || !graphEdges) initGraph();
  if(!graphNodes) return;

  const existingNodeIds = new Set(graphNodes.getIds());
  const existingEdgeIds = new Set(graphEdges.get().map(e => `${e.from}->${e.to}`));

  const newNodes = nodesList.filter(n => !existingNodeIds.has(n.id));
  if(newNodes.length > 0) graphNodes.add(newNodes);

  const newEdges = edgesList.filter(e => !existingEdgeIds.has(`${e.from}->${e.to}`));
  if(newEdges.length > 0) graphEdges.add(newEdges);
}

// ── Auto Pipeline Runner ──────────────────────────────────────
let pipelinePollInterval = null;

async function startAutoPipeline() {
  const target = document.getElementById('pipe-target').value.trim();
  const inScopeStr = document.getElementById('pipe-in-scope').value.trim();
  const outScopeStr = document.getElementById('pipe-out-scope').value.trim();

  if(!target) {
    alert('Please enter a target domain in the Pipeline tab!');
    return;
  }

  const inScope = inScopeStr ? inScopeStr.split(',').map(s => s.trim()) : [target];
  const outScope = outScopeStr ? outScopeStr.split(',').map(s => s.trim()) : [];

  const statusBox = document.getElementById('pipeline-status-box');
  statusBox.style.display = 'block';
  document.getElementById('pipe-step-name').textContent = '🚀 Launching Pipeline...';
  document.getElementById('pipe-step-status').textContent = `Target: ${target} | Enforcing Scope Guard...`;

  try {
    const r = await fetch('/api/pipeline/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target: target, in_scope: inScope, out_of_scope: outScope})
    });
    const d = await r.json();
    if(d.status === 'started') {
      document.getElementById('pipe-step-name').textContent = 'Pipeline Active';
      document.getElementById('pipe-step-status').textContent = `Session: ${d.session_id} running in background.`;
      
      // Auto-switch to Graph tab
      switchTab('graph', document.querySelector("button[onclick*='graph']"));
      refreshGraph();

      // Poll graph updates every 2.5s
      if(pipelinePollInterval) clearInterval(pipelinePollInterval);
      pipelinePollInterval = setInterval(refreshGraph, 2500);
    } else if(d.error) {
      alert(`Scope Guard Error: ${d.error}`);
    }
  } catch(err) {
    alert(`Pipeline error: ${err}`);
  }
}

// ── Deep HTTP & Burp Analyzer ────────────────────────────────
async function analyzeHTTPTraffic() {
  const rawReq = document.getElementById('http-raw-req').value.trim();
  const rawResp = document.getElementById('http-raw-resp').value.trim();
  const resDiv = document.getElementById('http-results');

  if(!rawReq) {
    alert('Please paste at least a Raw HTTP Request!');
    return;
  }

  resDiv.style.display = 'block';
  resDiv.innerHTML = '<div style="color:#aaa;padding:10px;">⏳ Analyzing HTTP request & response for vulnerabilities...</div>';

  try {
    const r = await fetch('/api/analyze-http', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({raw_request: rawReq, raw_response: rawResp})
    });
    const d = await r.json();

    if(d.error) {
      resDiv.innerHTML = `<div style="color:red;padding:10px;">Error: ${escHtml(d.error)}</div>`;
      return;
    }

    let html = `
      <div style="background:#111;border:1px solid #333;border-radius:6px;padding:15px;margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <h3 style="margin:0;color:#00ff41;">Analysis Results (${d.findings_count} Findings)</h3>
          <span style="background:#220000;color:#ff3333;padding:4px 10px;border-radius:4px;font-weight:bold;">Risk Score: ${d.risk_score}/100</span>
        </div>
        <div style="display:flex;gap:10px;font-size:12px;margin-bottom:15px;">
          <span style="color:#ff3333;">Critical: ${d.severity_summary.Critical}</span>
          <span style="color:#ff6600;">High: ${d.severity_summary.High}</span>
          <span style="color:#ffaa00;">Medium: ${d.severity_summary.Medium}</span>
          <span style="color:#00aa00;">Low: ${d.severity_summary.Low}</span>
          <span style="color:#3399ff;">Info: ${d.severity_summary.Info}</span>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px;">
    `;

    for(const f of d.findings) {
      const col = ss(f.severity);
      html += `
        <div style="background:#181818;border:1px solid #282828;border-radius:6px;padding:10px 14px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <strong style="color:#fff;font-size:13px;">${escHtml(f.title)}</strong>
            <span style="padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;${col}">${escHtml(f.severity)}</span>
          </div>
          <p style="color:#bbb;font-size:12px;margin:4px 0;">${escHtml(f.description)}</p>
          ${f.evidence ? `<pre style="background:#050505;color:#ffaa00;padding:6px;border-radius:4px;font-size:11px;overflow-x:auto;">${escHtml(f.evidence)}</pre>` : ''}
          <div style="color:#00ff41;font-size:11px;margin-top:4px;">💡 Recommendation: ${escHtml(f.recommendation)}</div>
        </div>
      `;
    }

    html += `</div></div>`;
    resDiv.innerHTML = html;

  } catch(err) {
    resDiv.innerHTML = `<div style="color:red;padding:10px;">Analysis Failed: ${err}</div>`;
  }
}

// ── Skills & Triage Management ──────────────────────────────
async function loadSkills() {
  const container = document.getElementById('skills-list');
  if(!container) return;
  try {
    const r = await fetch('/api/skills');
    const d = await r.json();
    const skills = d.skills || [];
    if(!skills.length) {
      container.innerHTML = '<div style="color:#666;font-size:12px;">لا توجد مهارات محفوظة بعد.</div>';
      return;
    }
    container.innerHTML = skills.map(s => `
      <div style="background:#181818;border:1px solid #282828;border-radius:4px;padding:6px 10px;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <strong style="color:#00ff41;font-size:12px;text-transform:uppercase;">${escHtml(s.category)}</strong>
          <span style="color:#666;font-size:10px;margin-left:6px;">(${s.size_bytes} B)</span>
        </div>
        <button onclick="deleteSkill('${escHtml(s.category)}')" style="background:none;border:none;color:#ff3333;cursor:pointer;font-size:11px;" title="حذف">🗑️</button>
      </div>
    `).join('');
  } catch(e) {
    container.innerHTML = `<div style="color:red;font-size:12px;">Failed to load skills: ${e}</div>`;
  }
}

async function trainNewSkill() {
  const cat = document.getElementById('skill-cat-inp').value.trim();
  const content = document.getElementById('skill-content-inp').value.trim();
  if(!cat || !content) {
    alert('يرجى كتابة اسم المهارة وتفاصيل التقرير أو الشرح!');
    return;
  }
  try {
    const r = await fetch('/api/skills/train', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({category: cat, writeup: content})
    });
    const d = await r.json();
    if(d.status === 'trained') {
      document.getElementById('skill-cat-inp').value = '';
      document.getElementById('skill-content-inp').value = '';
      alert(`[✓] تم تدريب وحفظ مهارة (${cat}) في ذاكرة الـ AI بنجاح!`);
      loadSkills();
    }
  } catch(e) {
    alert(`Failed to train skill: ${e}`);
  }
}

async function deleteSkill(cat) {
  if(!confirm(`هل أنت متأكد من حذف مهارة "${cat}" من ذاكرة الـ AI؟`)) return;
  try {
    await fetch(`/api/skills/${cat}`, {method: 'DELETE'});
    loadSkills();
  } catch(e) {}
}

async function runSkillTriageScan() {
  const url = document.getElementById('skill-target-url').value.trim();
  const cookie = document.getElementById('skill-target-cookie').value.trim();
  const outDiv = document.getElementById('skill-scan-output');
  const btn = document.getElementById('skill-scan-btn');

  if(!url) {
    alert('يرجى إدخال رابط الهدف!');
    return;
  }

  btn.disabled = true;
  outDiv.style.display = 'block';
  outDiv.innerHTML = `
    <div style="color:#aaa;">⏳ جاري الزحف واستخراج النماذج والباراميترات عبر Burp Suite...</div>
    <div style="color:#3399ff;">🧠 جاري مطابقة الباراميترات مع مهارات الـ AI والتحقق بدون هلوسة...</div>
  `;

  try {
    const r = await fetch('/api/skills/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: url, cookie: cookie})
    });
    const d = await r.json();

    if(d.error) {
      outDiv.innerHTML = `<div style="color:red;">[!] Error: ${escHtml(d.error)}</div>`;
      btn.disabled = false;
      return;
    }

    outDiv.innerHTML = `
      <div style="color:#00ff41;font-weight:bold;margin-bottom:8px;">[✓] اكتمل فحص الـ Triage المعتمد على المهارات بنجاح!</div>
      <div style="color:#aaa;font-size:11px;margin-bottom:10px;line-height:1.6;">
        🛡️ التقنيات المكتشفة: <strong style="color:#ffaa00;">${escHtml((d.crawl_summary?.tech_stack || []).join(', ') || 'Standard Web')}</strong><br>
        📊 الباراميترات: <span style="color:#3399ff;font-weight:bold;">${d.crawl_summary?.params_count || 0}</span> |
        النماذج (Forms): <span style="color:#3399ff;font-weight:bold;">${d.crawl_summary?.forms_count || 0}</span> |
        نقاط الـ API المستخرجة من الـ JS: <span style="color:#00ff41;font-weight:bold;">${d.crawl_summary?.api_endpoints_count || 0}</span>
      </div>
      
      <div style="background:#111;border:1px solid #3399ff;border-radius:4px;padding:8px;margin-bottom:10px;">
        <div style="color:#3399ff;font-weight:bold;margin-bottom:4px;">1. قرار الـ Router ومطابقة المهارات:</div>
        <div style="color:#ddd;white-space:pre-wrap;">${escHtml(d.router_decision || '')}</div>
      </div>

      <div style="background:#111;border:1px solid #00ff41;border-radius:4px;padding:8px;">
        <div style="color:#00ff41;font-weight:bold;margin-bottom:4px;">2. تقرير الـ Triage والتحقق النهائي (Anti-Hallucination):</div>
        <div style="color:#fff;white-space:pre-wrap;">${escHtml(d.final_triage_report || '')}</div>
      </div>
    `;
  } catch(e) {
    outDiv.innerHTML = `<div style="color:red;">Scan failed: ${e}</div>`;
  } finally {
    btn.disabled = false;
  }
}

// ── Autonomous Self-Learning Management ─────────────────────
async function loadLearningData() {
  const topicsContainer = document.getElementById('topics-list');
  const historyContainer = document.getElementById('learning-history-list');
  if(!topicsContainer) return;

  try {
    const [rTopics, rHistory] = await Promise.all([
      fetch('/api/learning/topics').then(r => r.json()),
      fetch('/api/learning/history').then(r => r.json())
    ]);

    const topics = rTopics.topics || [];
    topicsContainer.innerHTML = topics.map(t => `
      <div style="background:#181818;border:1px solid #282828;border-radius:4px;padding:8px 10px;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <strong style="color:#3399ff;font-size:12px;">${escHtml(t.title)}</strong>
          <div style="color:#888;font-size:11px;margin-top:2px;">${escHtml(t.description)}</div>
        </div>
        <button onclick="startTopicLearning('${escHtml(t.id)}')" class="btn-sm" style="background:#00ff41;color:#000;font-weight:bold;margin-left:10px;white-space:nowrap;">🧠 تعلّم الآن</button>
      </div>
    `).join('');

    const history = rHistory.history || [];
    if(!history.length) {
      historyContainer.innerHTML = '<div>لا توجد سجلات سابقة.</div>';
    } else {
      historyContainer.innerHTML = history.slice(0, 5).map(h => `
        <div style="padding:3px 0;border-bottom:1px solid #222;">
          <span style="color:#00ff41;">[${escHtml(h.timestamp)}]</span>
          <strong style="color:#fff;margin-left:4px;">${escHtml(h.title)}</strong>
        </div>
      `).join('');
    }
  } catch(e) {
    topicsContainer.innerHTML = `<div style="color:red;">فشل تحميل المناهج: ${e}</div>`;
  }
}

async function startTopicLearning(topicId) {
  const consoleDiv = document.getElementById('learning-console');
  consoleDiv.innerHTML = `<div style="color:#aaa;">⏳ جاري بدء دورة التعلم الذاتي للموديلات الأمنية...</div>`;

  try {
    const r = await fetch('/api/learning/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({topic_id: topicId})
    });
    const d = await r.json();

    if(d.error) {
      consoleDiv.innerHTML = `<div style="color:red;">[!] Error: ${escHtml(d.error)}</div>`;
      return;
    }

    consoleDiv.innerHTML = `
      <div style="color:#00ff41;font-weight:bold;">[✓] اكتملت دورة التعلم الذاتي بنجاح! 🎉</div>
      <div style="color:#3399ff;font-size:11px;margin-top:4px;">الموضوع: ${escHtml(d.topic)}</div>
      <div style="color:#aaa;font-size:11px;">تم التحديث في: data/skills/${escHtml(d.category)}.txt</div>
      <div style="color:#ffaa00;font-size:11px;margin-top:4px;">📌 إشعار Qwen Coder: ${escHtml(d.qwen_summary || '')}</div>
      <div style="background:#111;border:1px solid #333;border-radius:4px;padding:6px;margin-top:8px;font-size:11px;color:#ddd;white-space:pre-wrap;">${escHtml(d.synthesized_skill || '')}</div>
    `;
    loadLearningData();
  } catch(e) {
    consoleDiv.innerHTML = `<div style="color:red;">فشل التعلم: ${e}</div>`;
  }
}

async function startGlobalBrainLearning() {
  const btn = document.getElementById('learn-global-btn');
  const consoleDiv = document.getElementById('learning-console');
  if(btn) btn.disabled = true;
  consoleDiv.innerHTML = `<div style="color:#00e5ff;">🧠 [GLOBAL LEARNING] جاري بدء دورة التعلم الذاتي التلقائي من كافة المصادر العالمية المعتمدة (NVD, CISA KEV, GitHub, Medium, PortSwigger, Exploit-DB)...</div>`;

  try {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${location.host}/ws/learn`;
    const learnWs = new WebSocket(wsUrl);

    learnWs.onopen = () => {
      learnWs.send(JSON.stringify({source: 'all', limit: 10}));
      consoleDiv.innerHTML += `<div style="color:#3399ff;">⚡ تم الاتصال بمحرك التعلم الذاتي... جاري سحب وتحليل الثغرات وسلاسل الاستغلال في الوقت الفعلي:</div>`;
    };

    learnWs.onmessage = (event) => {
      try {
        const d = JSON.parse(event.data);
        if(d.event === 'learning_log' || d.event === 'log') {
          consoleDiv.innerHTML += `<div style="color:#00ff41;margin:2px 0;">[LOG] ${escHtml(d.message || '')}</div>`;
          consoleDiv.scrollTop = consoleDiv.scrollHeight;
        } else if(d.event === 'learning_done' || d.event === 'done') {
          consoleDiv.innerHTML += `
            <div style="color:#00e5ff;font-weight:bold;margin-top:8px;border-top:1px solid #333;padding-top:6px;">
              [✓] اكتملت دورة التعلم الذاتي العالمية الشاملة بنجاح! 🎉
              <br>📊 المقالات المحللة: ${d.articles_analyzed || 0} | الـ CVEs: ${d.cves_added || 0} | الـ Payloads: ${d.payloads_added || 0}
            </div>`;
          consoleDiv.scrollTop = consoleDiv.scrollHeight;
          if(btn) btn.disabled = false;
          loadLearningData();
          learnWs.close();
        }
      } catch(e) {}
    };

    learnWs.onerror = async () => {
      // Fallback to REST API
      const r = await fetch('/api/brain/learn', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({source: 'all', limit: 10})
      });
      const res = await r.json();
      consoleDiv.innerHTML += `<div style="color:#00ff41;">[✓] اكتمل التعلم الذاتي عبر الـ API! تم تحديث المعرفة بنجاح.</div>`;
      if(btn) btn.disabled = false;
    };
  } catch(err) {
    consoleDiv.innerHTML += `<div style="color:red;">خطأ في الاتصال: ${err}</div>`;
    if(btn) btn.disabled = false;
  }
}

async function startAllLearning() {
  const btn = document.getElementById('learn-all-btn');
  const consoleDiv = document.getElementById('learning-console');
  btn.disabled = true;
  consoleDiv.innerHTML = `<div style="color:#00ff41;">⏳ جاري تشغيل دورة التعلم الذاتي الشاملة لكافة لابات PortSwigger ومناهج الـ Bug Bounty... قد تستغرق ثوانٍ معدودة.</div>`;

  try {
    const r = await fetch('/api/learning/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({topic_id: 'all'})
    });
    const d = await r.json();

    consoleDiv.innerHTML = `
      <div style="color:#00ff41;font-weight:bold;">[✓] اكتملت دورة التعلم الذاتي الشاملة! تم تدريب (${d.total_learned || 0}) مناهج ولابات بنجاح! 🚀</div>
      <div style="color:#aaa;font-size:11px;margin-top:6px;">أصبحت الموديلات الأمنية الآن تمتلك أحدث تقنيات PortSwigger في الذاكرة الحية.</div>
    `;
    loadLearningData();
  } catch(e) {
    consoleDiv.innerHTML = `<div style="color:red;">فشل التعلم الشامل: ${e}</div>`;
  } finally {
    btn.disabled = false;
  }
}

async function runLiveScrape() {
  let source = document.getElementById('scrape-source-sel').value;
  const custom = document.getElementById('scrape-custom-inp').value.trim();
  const consoleDiv = document.getElementById('learning-console');
  const btn = document.getElementById('scrape-btn');

  btn.disabled = true;

  const payload = {source: source, limit: 10};
  if(custom.startsWith('http://') || custom.startsWith('https://')) {
    source = 'url';
    payload.source = 'url';
    payload.url = custom;
  } else if(source === 'url') {
    payload.url = custom;
  } else if(source === 'github') {
    payload.query = custom || 'bug bounty writeup';
  } else if(source === 'medium') {
    payload.tag = custom || 'bug-bounty';
  }

  consoleDiv.innerHTML = `<div style="color:#ffaa00;">⏳ جاري سحب وتحليل المحتوى من [${source.toUpperCase()}] وفهرسته في Vector DB...</div>`;

  try {
    const r = await fetch('/api/learning/scrape', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    const d = await r.json();

    if(d.status === 'success') {
      consoleDiv.innerHTML = `
        <div style="color:#00ff41;font-weight:bold;">[✓] تم سحب وتعلم المحتوى بنجاح! 📥</div>
        <div style="color:#fff;font-size:11px;margin-top:4px;">المصدر: ${escHtml(d.source)} | المقالات المسحوبة: ${d.scraped_writeups} | مهارات جديدة أضيفت: ${d.new_skills_added}</div>
        <div style="color:#3399ff;font-size:11px;">إجمالي المهارات في قاعدة البيانات المتجهة (Vector DB): ${d.total_skills_in_db}</div>
      `;
      loadSkills();
      loadLearningData();
    } else {
      consoleDiv.innerHTML = `<div style="color:#ffaa00;">[!] تم فحص المصدر (${escHtml(d.source || source)}) — لا توجد مقالات جديدة غير مكررة حالياً.</div>`;
    }
  } catch(e) {
    consoleDiv.innerHTML = `<div style="color:red;">فشل السحب والتعلم: ${e}</div>`;
  } finally {
    btn.disabled = false;
  }
}

// ── Live Differential PoC & False Positive Verifier ─────────
async function runDifferentialPoC() {
  const targetUrl = document.getElementById('poc-target-url').value.trim();
  const paramName = document.getElementById('poc-param-name').value.trim();
  const vulnType = document.getElementById('poc-vuln-type').value;
  const resBox = document.getElementById('poc-results-box');
  const btn = document.getElementById('poc-run-btn');

  if(!targetUrl || !paramName) {
    alert('يرجى إدخال رابط الهدف واسم الباراميتر المطلوب فحصه!');
    return;
  }

  btn.disabled = true;
  resBox.style.display = 'block';
  resBox.innerHTML = '<div style="color:#ffaa00;padding:12px;">⏳ جاري تنفيذ الفحص التفاضلي الثلاثي (Baseline vs Exploit vs Control) والتحقق من الـ WAF...</div>';

  try {
    const r = await fetch('/api/probe/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target_url: targetUrl, param_name: paramName, vuln_type: vulnType})
    });
    const d = await r.json();

    if(d.error) {
      resBox.innerHTML = `<div style="color:red;padding:12px;">Error: ${escHtml(d.error)}</div>`;
      return;
    }

    const isVer = d.verified;
    const cvss = d.cvss || {};
    const statusCol = isVer ? '#ff2a4b' : '#00ff41';
    const statusText = isVer ? '🔴 ثغرة حقيقية مؤكدة (VERIFIED VULNERABILITY)' : '🟢 ثغرة منفيّة - تقرير وهمي تم إعدامه (FALSE POSITIVE REJECTED)';

    resBox.innerHTML = `
      <div style="background:#090d14;border:1px solid ${statusCol};border-radius:8px;padding:15px;margin-top:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <h3 style="margin:0;color:${statusCol};">${statusText}</h3>
          <span style="background:#111;color:${cvss.color || '#fff'};border:1px solid ${cvss.color || '#444'};padding:4px 10px;border-radius:6px;font-weight:bold;">
            CVSS v3.1: ${cvss.score || '0.0'} (${cvss.severity || 'N/A'})
          </span>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;font-size:12px;">
          <div><strong>🎯 الهدف:</strong> <code style="color:#3399ff;">${escHtml(d.target_url)}</code></div>
          <div><strong>📊 الباراميتر:</strong> <code style="color:#ffaa00;">${escHtml(d.param_name)}</code></div>
          <div><strong>🛡️ جدار الحماية (WAF):</strong> <span>${escHtml((d.waf_info?.wafs || ['None']).join(', '))}</span></div>
          <div><strong>⏱️ زمن الاستجابة:</strong> <span>${d.duration_sec} ثانية</span></div>
        </div>

        <div style="background:#05070a;border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:10px;font-size:12px;margin-bottom:10px;">
          <strong style="color:#00ff41;">🔍 الدليل التقني للتحقق (Proof Reason):</strong>
          <div style="color:#ddd;margin-top:4px;">${escHtml(d.proof_reason || '')}</div>
        </div>

        ${cvss.vector ? `<div style="font-size:11px;color:#888;font-family:monospace;">Vector: ${escHtml(cvss.vector)}</div>` : ''}
      </div>
    `;
  } catch(e) {
    resBox.innerHTML = `<div style="color:red;padding:12px;">فشل الفحص: ${e}</div>`;
  } finally {
    btn.disabled = false;
  }
}

// ── Live Browser Controller ─────────────────────────────────
async function launchLiveBrowser() {
  const target = getTargetUrl();
  if(!target) {
    alert('يرجى إدخال رابط الهدف في خانة Target URL أولاً!');
    return;
  }
  const useProxy = document.getElementById('use-proxy-chk')?.checked || false;
  
  const outEl = document.getElementById('output-panel');
  if(outEl) outEl.style.display = 'block';
  
  log('i', `\n[BROWSER AGENT] 🧭 جاري فتح نافذة المتصفح الحية والتحكم التلقائي في الهدف: ${target}...`);
  if(useProxy) {
    log('c', `[PROXY] تم ربط وتوجيه متصفح الفحص عبر Burp Suite Proxy (127.0.0.1:8080) لالتقاط الترافيك`);
  }

  try {
    const r = await fetch('/api/browser/browse', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: target, visible: true, use_proxy: useProxy})
    });
    const d = await r.json();
    if(d.status === 'success') {
      const bName = (d.active_browser || 'Browser').toUpperCase();
      log('s', `[✓] تم تشغيل متصفح [${bName}] والتحكم في الهدف بنجاح!`);
      log('i', `    عنوان الصفحة: ${d.title}`);
      log('i', `    العناصر المكتشفة: ${d.interactive_elements.forms.length} نماذج إدخال, ${d.interactive_elements.inputs.length} حقول, ${d.interactive_elements.buttons.length} أزرار تفاعلية`);
      log('s', `[+] تم تمرير الطلبات وكوكيز الجلسة بنجاح إلى Burp Suite!`);
    } else {
      log('e', `[!] خطأ في تشغيل المتصفح: ${d.error || 'Unknown error'}`);
    }
  } catch(e) {
    log('e', `[!] فشل الاتصال بمحرك المتصفح: ${e}`);
  }
}

// ── Security Intelligence Hub & Multi-Mode Controls ───────────
let currentActiveQuiz = null;

async function loadIntelligenceHub() {
  try {
    const r = await fetch('/api/intelligence/status');
    const d = await r.json();
    
    // Subsystem indicators
    const subs = d.subsystems || {};
    if(document.getElementById('si-sub-brain')) document.getElementById('si-sub-brain').textContent = subs.autonomous_brain === 'connected' ? '🟢 متصل (OODA)' : '🔴 غير متصل';
    if(document.getElementById('si-sub-burp')) document.getElementById('si-sub-burp').textContent = subs.burp_agent ? `🎧 ${subs.burp_agent}` : '—';
    if(document.getElementById('si-sub-intel')) document.getElementById('si-sub-intel').textContent = subs.security_intelligence === 'active' ? '🧠 نشط (Hypotheses)' : '—';
    if(document.getElementById('si-sub-scope')) document.getElementById('si-sub-scope').textContent = subs.scope_guard ? '🛡️ حماية صارمة' : '—';
    if(document.getElementById('si-sub-bus')) document.getElementById('si-sub-bus').textContent = subs.event_bus ? '⚡ جسر موحد' : '—';

    // Populate Scope Fields
    const sc = d.scope || {};
    if(sc.target && !document.getElementById('si-scope-target').value) {
      document.getElementById('si-scope-target').value = sc.target;
    }
    if(sc.allowed_domains && sc.allowed_domains.length && !document.getElementById('si-scope-allowed').value) {
      document.getElementById('si-scope-allowed').value = sc.allowed_domains.join(', ');
    }
    if(sc.excluded_paths && sc.excluded_paths.length && !document.getElementById('si-scope-excluded').value) {
      document.getElementById('si-scope-excluded').value = sc.excluded_paths.join(', ');
    }
    if(document.getElementById('si-scope-active-chk')) {
      document.getElementById('si-scope-active-chk').checked = Boolean(sc.allow_active_tests);
    }

    // Learning Profile
    const prof = d.learning_profile || {};
    if(document.getElementById('si-user-level')) {
      document.getElementById('si-user-level').textContent = prof.current_level || 'مبتدئ (Beginner)';
    }
    if(document.getElementById('si-user-xp')) {
      document.getElementById('si-user-xp').textContent = `${prof.total_xp || 0} XP`;
    }
  } catch(e) {
    console.warn('loadIntelligenceHub failed:', e);
  }
}

async function saveScopePolicy() {
  const target = document.getElementById('si-scope-target').value.trim();
  const allowed = document.getElementById('si-scope-allowed').value.split(',').map(s=>s.trim()).filter(Boolean);
  const excluded = document.getElementById('si-scope-excluded').value.split(',').map(s=>s.trim()).filter(Boolean);
  const allowActive = document.getElementById('si-scope-active-chk').checked;

  const msg = document.getElementById('si-scope-status-msg');
  msg.style.display = 'block';
  msg.style.color = '#ffaa00';
  msg.textContent = 'جاري حفظ وتطبيق سياسة النطاق...';

  try {
    const r = await fetch('/api/intelligence/scope', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        target: target || '*',
        allowed_domains: allowed,
        excluded_paths: excluded,
        allow_active_tests: allowActive
      })
    });
    const d = await r.json();
    msg.style.color = '#00ff41';
    msg.textContent = `✓ تم تطبيق النطاق بنجاح! الوضع الحالي: ${d.mode} على الهدف: ${d.target}`;
  } catch(e) {
    msg.style.color = '#ff2a4b';
    msg.textContent = `خطأ في تطبيق النطاق: ${e}`;
  }
}

async function generateExplanation() {
  const subject = document.getElementById('si-explain-subject').value.trim();
  if(!subject) {
    alert('يرجى إدخال اسم المفهوم أو الثغرة المراد شرحها!');
    return;
  }
  const box = document.getElementById('si-explain-box');
  const content = document.getElementById('si-explain-content');
  box.style.display = 'block';
  content.innerHTML = '<div style="color:#ffaa00;">⏳ جاري إعداد الشرح المعرفي من المعلم الأمني...</div>';

  try {
    const r = await fetch('/api/intelligence/explain', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({subject: subject, language: 'ar'})
    });
    const d = await r.json();
    const exp = d.explanations || {};

    content.innerHTML = `
      <div style="font-weight:bold;color:#00ccff;font-size:14px;margin-bottom:8px;">📖 الشرح الشامل لـ: ${d.subject}</div>
      <div style="margin-bottom:10px;background:rgba(0,255,65,0.06);border-left:3px solid #00ff41;padding:8px 10px;">
        <strong style="color:#00ff41;">1. ببساطة (ELI5):</strong>
        <p style="margin:4px 0 0 0;color:#eee;">${exp.simple || '—'}</p>
      </div>
      <div style="margin-bottom:10px;background:rgba(0,204,255,0.06);border-left:3px solid #00ccff;padding:8px 10px;">
        <strong style="color:#00ccff;">2. ميكانيكية الثغرة الفنية (Technical Mechanics):</strong>
        <p style="margin:4px 0 0 0;color:#eee;">${exp.technical || '—'}</p>
      </div>
      <div style="margin-bottom:10px;background:rgba(255,170,0,0.06);border-left:3px solid #ffaa00;padding:8px 10px;">
        <strong style="color:#ffaa00;">3. منظور البينتستر والاختبار العملي (Pentester Perspective):</strong>
        <p style="margin:4px 0 0 0;color:#eee;">${exp.pentester || '—'}</p>
      </div>
      <div style="background:rgba(255,42,75,0.06);border-left:3px solid #ff2a4b;padding:8px 10px;">
        <strong style="color:#ff2a4b;">4. منظور الباحث والترقيع البرمجي (Remediation & Defense):</strong>
        <p style="margin:4px 0 0 0;color:#eee;">${exp.researcher || '—'}</p>
      </div>
    `;
  } catch(e) {
    content.innerHTML = `<div style="color:#ff2a4b;">خطأ في توليد الشرح: ${e}</div>`;
  }
}

async function startQuizScenario() {
  const topic = document.getElementById('si-quiz-topic').value;
  const container = document.getElementById('si-quiz-container');
  container.innerHTML = '<div style="color:#ffaa00;padding:15px;text-align:center;">⏳ جاري بناء سيناريو السؤال التفاعلي...</div>';

  try {
    const r = await fetch('/api/intelligence/quiz/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({topic: topic})
    });
    const q = await r.json();
    currentActiveQuiz = q;

    const choices = q.options || q.choices || [];
    const choicesHtml = choices.map((ch, idx) => `
      <button onclick="submitQuizAnswer(${idx})" class="btn-sec" style="text-align:right;width:100%;padding:10px 14px;background:#090d14;border:1px solid rgba(255,255,255,0.1);border-radius:6px;cursor:pointer;color:#eee;font-size:13px;transition:0.2s;">
        <span style="color:#00ccff;font-weight:bold;margin-left:6px;">[${idx + 1}]</span> ${ch}
      </button>
    `).join('');

    container.innerHTML = `
      <div style="background:#05070a;border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:14px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
          <span style="color:#ffaa00;font-size:12px;font-weight:bold;">سيناريو: ${q.topic}</span>
          <span style="color:#aaa;font-size:11px;">المفهوم: ${q.concept_tested || 'Security'}</span>
        </div>
        <div style="font-size:14px;color:#fff;font-weight:500;line-height:1.5;margin-bottom:14px;">
          ${q.scenario || q.question || 'تفاصيل السيناريو:'}
        </div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          ${choicesHtml}
        </div>
        <div id="si-quiz-feedback" style="display:none;margin-top:12px;padding:10px;border-radius:6px;font-size:13px;"></div>
      </div>
    `;
  } catch(e) {
    container.innerHTML = `<div style="color:#ff2a4b;padding:10px;">خطأ في تحميل الاختبار: ${e}</div>`;
  }
}

async function submitQuizAnswer(choiceIdx) {
  if(!currentActiveQuiz) return;
  const feedback = document.getElementById('si-quiz-feedback');
  feedback.style.display = 'block';
  feedback.innerHTML = '<div style="color:#ffaa00;">⏳ جاري تقييم الإجابة وتحديث ملف التعلم...</div>';

  try {
    const r = await fetch('/api/intelligence/quiz/evaluate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        quiz: currentActiveQuiz,
        choice_idx: choiceIdx
      })
    });
    const evalResult = await r.json();

    const isCorrect = evalResult.is_correct;
    feedback.style.background = isCorrect ? 'rgba(0,255,65,0.1)' : 'rgba(255,42,75,0.1)';
    feedback.style.border = `1px solid ${isCorrect ? '#00ff41' : '#ff2a4b'}`;
    feedback.style.color = isCorrect ? '#00ff41' : '#ff2a4b';

    feedback.innerHTML = `
      <div style="font-weight:bold;font-size:14px;margin-bottom:6px;">
        ${isCorrect ? '🎉 إجابة صحيحة! أحسنت التحليل الأمني.' : '❌ إجابة غير صحيحة.'}
        <span style="font-size:12px;color:#00ccff;margin-right:8px;">(درجة الفهم: ${(evalResult.understanding_score * 100).toFixed(0)}%)</span>
      </div>
      <div style="color:#eee;font-size:12px;line-height:1.5;">${evalResult.feedback_ar || evalResult.explanation || ''}</div>
      <div style="color:#aaa;font-size:11px;margin-top:6px;">💡 التوصية التالية: ${evalResult.next_recommendation || 'تابع التدريب'}</div>
    `;

    // Refresh profile display
    loadIntelligenceHub();
  } catch(e) {
    feedback.innerHTML = `<div style="color:#ff2a4b;">خطأ في تقييم الإجابة: ${e}</div>`;
  }
}


async function runThreatResearch() {
  const topic = document.getElementById('si-research-input').value.trim();
  if(!topic) return;
  const resEl = document.getElementById('si-research-result');
  resEl.style.display = 'block';
  resEl.innerHTML = '<div style="color:#ffaa00;">⏳ جاري البحث في قواعد البيانات ومصادر CVE...</div>';

  try {
    const r = await fetch('/api/intelligence/research', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({topic: topic})
    });
    const d = await r.json();
    resEl.innerHTML = `
      <div style="color:#00ccff;font-weight:bold;margin-bottom:4px;">${d.topic} (Severity: ${d.severity || 'Medium'})</div>
      <div style="color:#aaa;margin-bottom:4px;">${d.summary || '—'}</div>
      <div style="font-size:10px;color:#777;">Sources: ${(d.sources || []).join(', ')} | Cached: ${d.cached ? 'Yes (TTL)' : 'Live'}</div>
    `;
  } catch(e) {
    resEl.innerHTML = `<div style="color:#ff2a4b;">خطأ في البحث: ${e}</div>`;
  }
}

