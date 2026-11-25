/* ==========================================================================
   HunterAI Unified Platform Client (window.HunterPlatform)
   - Single-origin state store synced via SSE (/api/platform/stream)
   - Cross-page CustomEvents ('hunter:state', 'hunter:event', 'hunter:navigate')
   - Global Command Palette & Cross-Domain Search modal (Ctrl+K)
   Works standalone across index.html, opencode.html, chat.html, and command.html.
   ========================================================================== */
(function (global) {
  'use strict';

  var Core = global.HunterCore || null;

  function escHtml(val) {
    if (Core && typeof Core.escapeHtml === 'function') {
      return Core.escapeHtml(val);
    }
    if (val === null || val === undefined) return '';
    return String(val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function safeEl(tag, attrs, children) {
    if (Core && typeof Core.el === 'function') {
      return Core.el(tag, attrs, children);
    }
    var node = document.createElement(tag);
    if (attrs && typeof attrs === 'object') {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined) return;
        if (k === 'class' || k === 'className') node.className = String(v);
        else if (k === 'text' || k === 'textContent') node.textContent = String(v);
        else if (k.indexOf('on') === 0 && typeof v === 'function') {
          node.addEventListener(k.slice(2).toLowerCase(), v);
        } else if (k === 'dataset' && typeof v === 'object') {
          Object.keys(v).forEach(function (dk) {
            if (v[dk] !== null && v[dk] !== undefined) node.dataset[dk] = String(v[dk]);
          });
        } else {
          node.setAttribute(k, String(v));
        }
      });
    }
    if (children !== undefined && children !== null) {
      var list = Array.isArray(children) ? children : [children];
      list.forEach(function (c) {
        if (c === null || c === undefined || c === false || c === true) return;
        if (typeof Node !== 'undefined' && c instanceof Node) node.appendChild(c);
        else node.appendChild(document.createTextNode(String(c)));
      });
    }
    return node;
  }

  function notify(msg, type) {
    if (Core && typeof Core.toast === 'function') {
      Core.toast(msg, type || 'info');
    }
  }

  function lang() {
    if (Core && typeof Core.getLang === 'function') return Core.getLang();
    if (typeof document !== 'undefined' && document.documentElement) {
      return document.documentElement.getAttribute('lang') === 'en' ? 'en' : 'ar';
    }
    return 'ar';
  }

  function tr(arText, enText) {
    return lang() === 'en' ? enText : arText;
  }

  function buildQueryPreserveParams(basePath, extraParams) {
    var theme = Core && Core.getTheme ? Core.getTheme() : (document.documentElement.getAttribute('data-theme') || 'dark');
    var currentLang = lang();
    var params = new URLSearchParams();
    params.set('theme', theme);
    params.set('lang', currentLang);
    if (extraParams && typeof extraParams === 'object') {
      Object.keys(extraParams).forEach(function (k) {
        if (extraParams[k] !== undefined && extraParams[k] !== null && extraParams[k] !== '') {
          params.set(k, String(extraParams[k]));
        }
      });
    }
    return basePath + '?' + params.toString();
  }

  /* ── Central Client Store ──────────────────────────────────────────────── */

  var state = {
    initialized: false,
    loading: false,
    connected: false,
    latest_seq: 0,
    context: {
      active_engagement_id: null,
      active_run_id: null,
      active_conversation_id: null,
      extra: {},
      updated_at: null
    },
    engagements: [],
    runs: [],
    approvals: {
      pending: [],
      recent: [],
      pending_count: 0
    },
    conversations: [],
    notifications: [],
    settings: {},
    services: {
      artex_go_core: { online: false, status: 'offline' },
      ollama: { online: false, host: 'http://127.0.0.1:11434' },
      lm_studio: { online: false, host: 'http://127.0.0.1:1234' },
      cloud_providers: [],
      burp_proxy: { online: false, host: '127.0.0.1:8080' },
      burp_agent: { online: false, host: '127.0.0.1:8085' }
    },
    counts: {
      engagements: 0,
      runs: 0,
      active_runs: 0,
      pending_approvals: 0,
      findings: 0,
      assets: 0,
      leads: 0,
      conversations: 0,
      unread_notifications: 0,
      tools_installed: 0,
      agents: 0
    },
    lastEvent: null,
    lastUpdatedAt: null
  };

  function getState() {
    return Object.assign({}, state, {
      context: Object.assign({}, state.context),
      approvals: Object.assign({}, state.approvals),
      services: Object.assign({}, state.services),
      counts: Object.assign({}, state.counts)
    });
  }

  function emitState(reason) {
    if (typeof window === 'undefined' || typeof CustomEvent !== 'function') return;
    window.dispatchEvent(
      new CustomEvent('hunter:state', {
        detail: Object.assign(getState(), { reason: reason || 'update' })
      })
    );
  }

  function emitPlatformEvent(ev) {
    state.lastEvent = ev;
    if (typeof window === 'undefined' || typeof CustomEvent !== 'function') return;
    window.dispatchEvent(new CustomEvent('hunter:event', { detail: ev }));
  }

  function applyOverviewPayload(data) {
    if (!data || typeof data !== 'object') return;
    if (data.context) state.context = Object.assign({}, state.context, data.context);
    if (Array.isArray(data.engagements)) state.engagements = data.engagements;
    if (Array.isArray(data.runs)) state.runs = data.runs;
    if (data.approvals && typeof data.approvals === 'object') {
      state.approvals = {
        pending: Array.isArray(data.approvals.pending) ? data.approvals.pending : [],
        recent: Array.isArray(data.approvals.recent) ? data.approvals.recent : [],
        pending_count: Number(data.approvals.pending_count || 0)
      };
    }
    if (Array.isArray(data.conversations)) state.conversations = data.conversations;
    if (Array.isArray(data.notifications)) state.notifications = data.notifications;
    if (data.settings && typeof data.settings === 'object') state.settings = data.settings;
    if (data.services && typeof data.services === 'object') {
      state.services = Object.assign({}, state.services, data.services);
    }
    if (data.counts && typeof data.counts === 'object') {
      state.counts = Object.assign({}, state.counts, data.counts);
    }
    if (typeof data.latest_seq === 'number' && data.latest_seq > state.latest_seq) {
      state.latest_seq = data.latest_seq;
    }
    state.initialized = true;
    state.lastUpdatedAt = Date.now();
  }

  async function apiJson(url, options) {
    var opts = Object.assign({ headers: { Accept: 'application/json' } }, options || {});
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
      opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
      opts.body = JSON.stringify(opts.body);
    }
    var res = await fetch(url, opts);
    var data = null;
    try {
      data = await res.json();
    } catch (_e) {
      data = null;
    }
    if (!res.ok) {
      var detail = (data && (data.detail && (typeof data.detail === 'string' ? data.detail : data.detail.reason))) || (data && (data.error || data.message)) || ('HTTP ' + res.status);
      var err = new Error(detail);
      err.status = res.status;
      err.payload = data;
      throw err;
    }
    return data || {};
  }

  var _overviewInFlight = null;
  var _refreshTimer = null;

  async function refreshOverview() {
    if (_overviewInFlight) return _overviewInFlight;
    state.loading = true;
    _overviewInFlight = apiJson('/api/platform/overview')
      .then(function (data) {
        applyOverviewPayload(data);
        emitState('overview');
        return getState();
      })
      .catch(function (err) {
        if (typeof console !== 'undefined' && console.warn) {
          console.warn('[HunterPlatform] overview error:', err && err.message ? err.message : err);
        }
        return getState();
      })
      .finally(function () {
        state.loading = false;
        _overviewInFlight = null;
      });
    return _overviewInFlight;
  }

  function scheduleRefresh(delayMs) {
    if (_refreshTimer !== null) clearTimeout(_refreshTimer);
    _refreshTimer = setTimeout(function () {
      _refreshTimer = null;
      refreshOverview();
    }, Math.max(80, delayMs || 200));
  }

  async function refreshEngagements() {
    var data = await apiJson('/api/platform/engagements');
    if (Array.isArray(data.engagements)) {
      state.engagements = data.engagements;
      state.counts.engagements = data.engagements.length;
    }
    if (data.go_core && typeof data.go_core === 'object') {
      state.services.artex_go_core = Object.assign({}, state.services.artex_go_core, {
        online: Boolean(data.go_core.online),
        error: data.go_core.error || null
      });
    }
    emitState('engagements');
    return data;
  }

  async function setContext(patch) {
    var data = await apiJson('/api/platform/context', {
      method: 'PUT',
      body: patch || {}
    });
    if (data.context) {
      state.context = Object.assign({}, state.context, data.context);
    }
    emitState('context');
    scheduleRefresh(150);
    return state.context;
  }

  function selectEngagement(engagementId) {
    return setContext({ active_engagement_id: engagementId || null });
  }

  async function createEngagement(payload) {
    var data = await apiJson('/api/platform/engagements', {
      method: 'POST',
      body: payload
    });
    if (data.engagement) {
      await refreshOverview();
    }
    return data;
  }

  async function startRun(payload) {
    var data = await apiJson('/api/platform/runs/start', {
      method: 'POST',
      body: payload
    });
    scheduleRefresh(120);
    return data;
  }

  async function pauseRun(runId) {
    var data = await apiJson('/api/platform/runs/' + encodeURIComponent(runId) + '/pause', { method: 'POST' });
    scheduleRefresh(120);
    return data;
  }

  async function resumeRun(runId) {
    var data = await apiJson('/api/platform/runs/' + encodeURIComponent(runId) + '/resume', { method: 'POST' });
    scheduleRefresh(120);
    return data;
  }

  async function stopRun(runId) {
    var data = await apiJson('/api/platform/runs/' + encodeURIComponent(runId) + '/stop', { method: 'POST' });
    scheduleRefresh(120);
    return data;
  }

  async function decideApproval(approvalId, decision, note) {
    var data = await apiJson('/api/platform/approvals/' + encodeURIComponent(approvalId) + '/decide', {
      method: 'POST',
      body: {
        decision: decision,
        note: note || '',
        decided_by: 'operator'
      }
    });
    await refreshOverview();
    return data;
  }

  async function markNotificationRead(notificationId) {
    var data = await apiJson('/api/platform/notifications/' + encodeURIComponent(notificationId) + '/read', {
      method: 'POST'
    });
    state.notifications = state.notifications.map(function (n) {
      if (n.notification_id === notificationId) {
        return Object.assign({}, n, { read: true });
      }
      return n;
    });
    state.counts.unread_notifications = state.notifications.filter(function (n) { return !n.read; }).length;
    emitState('notification_read');
    return data;
  }

  async function search(query, limit) {
    var q = (query || '').trim();
    if (!q) return { status: 'ok', query: '', total: 0, results: [], groups: {} };
    var url = '/api/platform/search?q=' + encodeURIComponent(q) + '&limit=' + encodeURIComponent(limit || 30);
    return apiJson(url);
  }

  async function artexRequest(path, options) {
    var clean = String(path || '').replace(/^\/+/, '');
    var url = '/api/platform/artex/' + clean;
    try {
      var res = await fetch(url, options || {});
      var data = await res.json().catch(function () { return {}; });
      return Object.assign({ http_status: res.status }, data);
    } catch (err) {
      return { online: false, status: 'offline', error: err.message };
    }
  }

  function getActiveEngagement() {
    var id = state.context && state.context.active_engagement_id;
    if (!state.engagements || !state.engagements.length) return null;
    if (id) {
      var found = state.engagements.find(function (e) { return e.engagement_id === id; });
      if (found) return found;
    }
    return state.engagements[0] || null;
  }

  function getActiveRun() {
    var rid = state.context && state.context.active_run_id;
    if (!state.runs || !state.runs.length) return null;
    if (rid) {
      var match = state.runs.find(function (r) { return r.run_id === rid; });
      if (match) return match;
    }
    return (
      state.runs.find(function (r) {
        return r.status === 'running' || r.status === 'paused' || r.status === 'pending';
      }) || state.runs[0] || null
    );
  }

  /* ── Navigation Event Bridge ───────────────────────────────────────────── */

  function navigate(target) {
    if (!target) return;
    var detail = typeof target === 'string' ? { section: target } : Object.assign({}, target);
    var sectionMap = {
      engagement: 'targets',
      run: 'runs',
      finding: 'results',
      asset: 'telemetry',
      lead: 'redteam',
      conversation: 'chat',
      tool: 'tools',
      skill: 'skills',
      approval: 'overview',
      file: 'editor'
    };
    if (!detail.section && detail.kind && sectionMap[detail.kind]) {
      detail.section = sectionMap[detail.kind];
    }

    var ev = new CustomEvent('hunter:navigate', { detail: detail, cancelable: true });
    var notCanceled = window.dispatchEvent(ev);

    if (!notCanceled) return;

    if (detail.kind === 'conversation' && detail.id && global.HunterCopilot && typeof global.HunterCopilot.selectConversation === 'function') {
      global.HunterCopilot.open();
      global.HunterCopilot.selectConversation(detail.id);
      return;
    }

    if (detail.section === 'runs' && typeof global.switchSection === 'function') {
      global.switchSection('overview');
      return;
    }

    if (detail.section && typeof global.switchSection === 'function') {
      var targetSec = document.getElementById('sec-' + detail.section);
      if (targetSec) {
        global.switchSection(detail.section);
        return;
      }
      if (detail.section === 'copilot' && global.HunterCopilot) {
        global.HunterCopilot.open();
        return;
      }
      if (detail.section === 'runs') {
        global.switchSection('overview');
        return;
      }
    }

    if (detail.section && typeof window !== 'undefined' && window.location) {
      var curPath = window.location.pathname || '/';
      if (curPath !== '/') {
        var sec = detail.section === 'runs' || detail.section === 'approvals' ? 'overview' : detail.section;
        if (sec === 'copilot' && global.HunterCopilot) {
          global.HunterCopilot.open();
          return;
        }
        window.location.href = buildQueryPreserveParams('/', { section: sec });
      }
    }
  }

  /* ── SSE Platform Stream with since_seq Replay & Exponential Backoff ───── */

  var _streamController = null;
  var _reconnectTimer = null;
  var _reconnectAttempt = 0;
  var _streamStarted = false;
  var _fallbackPoller = null;

  function handleIncomingSseEvent(eventName, dataText, idText) {
    if (!dataText) return;
    var parsed = null;
    try {
      parsed = JSON.parse(dataText);
    } catch (_e) {
      return;
    }
    var seq = Number((parsed && parsed.seq) || idText || 0);
    if (seq && seq > state.latest_seq) {
      state.latest_seq = seq;
    }
    var ev = Object.assign({ event_type: eventName || 'message' }, parsed || {});
    emitPlatformEvent(ev);

    var et = String(ev.event_type || '').toUpperCase();
    if (et === 'CONTEXT_UPDATED' && ev.payload) {
      state.context = Object.assign({}, state.context, ev.payload);
      emitState('sse_context');
    } else if (et.indexOf('RUN_') === 0 || et.indexOf('PIPELINE_') === 0 || et.indexOf('MISSION_') === 0) {
      if (ev.run_id && ev.payload && ev.payload.state) {
        var idx = state.runs.findIndex(function (r) { return r.run_id === ev.run_id; });
        if (idx >= 0) {
          state.runs[idx] = Object.assign({}, state.runs[idx], { status: ev.payload.state });
          emitState('sse_run');
        }
      }
      scheduleRefresh(220);
    } else if (et.indexOf('APPROVAL_') === 0 || et === 'ENGAGEMENT_CREATED' || et === 'SETTINGS_UPDATED') {
      scheduleRefresh(180);
    }
  }

  function scheduleReconnect() {
    if (_reconnectTimer !== null) return;
    if (typeof document !== 'undefined' && document.hidden) return;
    var delay = Math.min(30000, 1000 * Math.pow(2, Math.min(_reconnectAttempt, 5)));
    _reconnectAttempt += 1;
    _reconnectTimer = setTimeout(function () {
      _reconnectTimer = null;
      connectStream();
    }, delay);
  }

  function disconnectStream() {
    if (_reconnectTimer !== null) {
      clearTimeout(_reconnectTimer);
      _reconnectTimer = null;
    }
    if (_streamController) {
      try {
        _streamController.abort();
      } catch (_e) {
        /* ignore */
      }
      _streamController = null;
    }
    if (state.connected) {
      state.connected = false;
      emitState('disconnected');
    }
  }

  async function connectStream() {
    if (typeof fetch !== 'function' || typeof ReadableStream === 'undefined') {
      startFallbackPoller();
      return;
    }
    if (typeof document !== 'undefined' && document.hidden) {
      return;
    }
    disconnectStream();

    var controller = new AbortController();
    _streamController = controller;
    var url = '/api/platform/stream?since_seq=' + encodeURIComponent(state.latest_seq || 0) + '&heartbeat_s=15';

    try {
      var res = await fetch(url, {
        method: 'GET',
        headers: {
          Accept: 'text/event-stream',
          'Last-Event-ID': String(state.latest_seq || 0)
        },
        signal: controller.signal
      });
      if (!res.ok || !res.body) {
        throw new Error('SSE HTTP ' + res.status);
      }
      state.connected = true;
      _reconnectAttempt = 0;
      emitState('connected');

      var reader = res.body.getReader();
      var decoder = new TextDecoder('utf-8');
      var buffer = '';
      var curEvent = 'message';
      var curId = '';
      var curDataLines = [];

      function dispatchCurrentFrame() {
        if (curDataLines.length > 0) {
          handleIncomingSseEvent(curEvent, curDataLines.join('\n'), curId);
        }
        curEvent = 'message';
        curId = '';
        curDataLines = [];
      }

      while (true) {
        var chunk = await reader.read();
        if (chunk.done) {
          buffer += decoder.decode();
          break;
        }
        buffer += decoder.decode(chunk.value, { stream: true });
        var lines = buffer.split(/\r?\n/);
        buffer = lines.pop();
        for (var i = 0; i < lines.length; i += 1) {
          var line = lines[i];
          if (line === '') {
            dispatchCurrentFrame();
          } else if (line.charAt(0) === ':') {
            /* SSE comment heartbeat */
          } else if (line.indexOf('event:') === 0) {
            curEvent = line.slice(6).trim() || 'message';
          } else if (line.indexOf('id:') === 0) {
            curId = line.slice(3).trim();
          } else if (line.indexOf('data:') === 0) {
            curDataLines.push(line.slice(5).replace(/^ /, ''));
          }
        }
      }
      if (buffer.trim()) {
        if (buffer.indexOf('data:') === 0) curDataLines.push(buffer.slice(5).replace(/^ /, ''));
      }
      dispatchCurrentFrame();
      if (_streamController === controller && !controller.signal.aborted) {
        state.connected = false;
        emitState('stream_ended');
        scheduleReconnect();
      }
    } catch (err) {
      if (err && err.name === 'AbortError') return;
      state.connected = false;
      emitState('stream_error');
      scheduleReconnect();
    }
  }

  function startFallbackPoller() {
    if (_fallbackPoller || !Core || typeof Core.createVisibilityPoller !== 'function') return;
    _fallbackPoller = Core.createVisibilityPoller(refreshOverview, 5000, { immediate: true });
  }

  /* ── Shared Styles for Command Palette & Platform Overlay ──────────────── */

  function ensureStyles() {
    if (typeof document === 'undefined' || document.getElementById('hunter-platform-styles')) return;
    var css = [
      '.hp-palette-backdrop{position:fixed;inset:0;z-index:9500;background:rgba(2,6,23,0.72);display:none;align-items:flex-start;justify-content:center;padding:8vh 16px 24px;}',
      '.hp-palette-backdrop.is-open{display:flex;}',
      '.hp-palette-dialog{width:min(720px,100%);max-height:78vh;display:flex;flex-direction:column;background:var(--bg-surface,#111827);color:var(--text-primary,#f8fafc);border:1px solid var(--border-strong,#475569);border-radius:var(--radius-lg,12px);box-shadow:var(--shadow-md,0 8px 30px rgba(0,0,0,0.55));overflow:hidden;font-family:var(--font-sans,sans-serif);}',
      '.hp-palette-head{display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--border-subtle,#1f2937);background:var(--bg-elevated,#1a2332);}',
      '.hp-palette-input{flex:1;min-height:40px;background:var(--bg-inset,#070a10);color:var(--text-primary,#f8fafc);border:1px solid var(--border-subtle,#1f2937);border-radius:var(--radius-md,8px);padding:8px 12px;font-size:0.9375rem;font-family:var(--font-sans,sans-serif);}',
      '.hp-palette-input:focus-visible{outline:2px solid var(--accent-primary,#38bdf8);outline-offset:1px;}',
      '.hp-palette-close{min-width:44px;min-height:44px;background:transparent;color:var(--text-secondary,#cbd5e1);border:1px solid var(--border-subtle,#1f2937);border-radius:var(--radius-md,8px);cursor:pointer;font-size:1.1rem;display:inline-flex;align-items:center;justify-content:center;}',
      '.hp-palette-close:hover{background:var(--bg-surface,#111827);color:var(--text-primary,#f8fafc);border-color:var(--border-strong,#475569);}',
      '.hp-palette-body{flex:1;overflow-y:auto;padding:10px 12px 14px;display:flex;flex-direction:column;gap:12px;}',
      '.hp-palette-group-title{font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:var(--text-muted,#94a3b8);padding:4px 8px;}',
      '.hp-palette-item{width:100%;text-align:start;min-height:44px;padding:8px 12px;border-radius:var(--radius-md,8px);border:1px solid transparent;background:transparent;color:var(--text-primary,#f8fafc);cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:12px;font-family:inherit;}',
      '.hp-palette-item:hover,.hp-palette-item.is-selected{background:var(--accent-primary-bg,rgba(56,189,248,0.14));border-color:var(--accent-primary,#38bdf8);}',
      '.hp-palette-item-main{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1;}',
      '.hp-palette-item-title{font-size:0.875rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}',
      '.hp-palette-item-sub{font-size:0.75rem;color:var(--text-muted,#94a3b8);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}',
      '.hp-palette-kind{font-size:0.6875rem;font-family:var(--font-mono,monospace);padding:2px 8px;border-radius:999px;border:1px solid var(--border-subtle,#1f2937);background:var(--bg-inset,#070a10);color:var(--accent-primary,#38bdf8);flex-shrink:0;}',
      '.hp-palette-foot{display:flex;justify-content:space-between;align-items:center;padding:8px 14px;border-top:1px solid var(--border-subtle,#1f2937);font-size:0.75rem;color:var(--text-muted,#94a3b8);background:var(--bg-inset,#070a10);}',
      '.hp-kbd{font-family:var(--font-mono,monospace);font-size:0.72rem;padding:1px 6px;border:1px solid var(--border-strong,#475569);border-radius:4px;background:var(--bg-elevated,#1a2332);color:var(--text-secondary,#cbd5e1);}'
    ].join('\n');
    var style = document.createElement('style');
    style.id = 'hunter-platform-styles';
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }

  /* ── Command Palette & Global Search Modal (Ctrl+K) ────────────────────── */

  var _paletteEls = null;
  var _paletteOpen = false;
  var _paletteItems = [];
  var _selectedIndex = 0;
  var _searchDebounce = null;
  var _previousFocus = null;

  function buildQuickActions() {
    var actions = [
      { kind: 'action', id: 'nav-overview', title: tr('الانتقال: نظرة عامة والتشغيلات', 'Go to: Overview & Runs'), subtitle: 'sec-overview', run: function () { navigate({ section: 'overview' }); } },
      { kind: 'action', id: 'nav-targets', title: tr('الانتقال: الأهداف وحماية النطاق', 'Go to: Targets & Scope Guard'), subtitle: 'sec-targets', run: function () { navigate({ section: 'targets' }); } },
      { kind: 'action', id: 'nav-redteam', title: tr('الانتقال: مركز قيادة Red Team', 'Go to: Red Team Cockpit'), subtitle: 'sec-redteam', run: function () { navigate({ section: 'redteam' }); } },
      { kind: 'action', id: 'nav-telemetry', title: tr('الانتقال: خريطة مسار الهجوم و Wiretap', 'Go to: Attack Path & Wiretap'), subtitle: 'sec-telemetry', run: function () { navigate({ section: 'telemetry' }); } },
      { kind: 'action', id: 'nav-burp', title: tr('الانتقال: مراقب Burp Suite', 'Go to: Burp Suite Inspector'), subtitle: 'sec-burp', run: function () { navigate({ section: 'burp' }); } },
      { kind: 'action', id: 'nav-results', title: tr('الانتقال: النتائج والتقارير', 'Go to: Results & Reports'), subtitle: 'sec-results', run: function () { navigate({ section: 'results' }); } },
      { kind: 'action', id: 'nav-editor', title: tr('الانتقال: محرر الأكواد المتكامل', 'Go to: Integrated Code Editor'), subtitle: 'sec-editor', run: function () { navigate({ section: 'editor' }); } },
      { kind: 'action', id: 'toggle-copilot', title: tr('تبديل المساعد الذكي (Ctrl+J)', 'Toggle AI Copilot Drawer (Ctrl+J)'), subtitle: 'HunterCopilot', run: function () { if (global.HunterCopilot) global.HunterCopilot.toggle(); } },
      { kind: 'action', id: 'open-opencode', title: tr('فتح استوديو OpenCode Pro', 'Open OpenCode Pro Studio'), subtitle: '/opencode', run: function () { window.location.href = buildQueryPreserveParams('/opencode'); } },
      { kind: 'action', id: 'toggle-theme', title: tr('تبديل المظهر (داكن / فاتح)', 'Toggle Theme (Dark / Light)'), subtitle: 'HunterCore.toggleTheme()', run: function () { if (Core) Core.toggleTheme(); } },
      { kind: 'action', id: 'toggle-lang', title: tr('تبديل اللغة (العربية / English)', 'Toggle Language (AR / EN)'), subtitle: 'HunterCore.setLang()', run: function () { if (Core) Core.setLang(lang() === 'ar' ? 'en' : 'ar'); } }
    ];
    return actions;
  }

  function ensurePalette() {
    if (_paletteEls || typeof document === 'undefined' || !document.body) return _paletteEls;
    ensureStyles();

    var input = safeEl('input', {
      type: 'search',
      id: 'hunterCmdInput',
      class: 'hp-palette-input',
      autocomplete: 'off',
      'aria-label': tr('بحث شامل في المنصة والأوامر', 'Search engagements, runs, findings, tools, skills, or commands')
    });
    var closeBtn = safeEl(
      'button',
      {
        type: 'button',
        class: 'hp-palette-close',
        'aria-label': tr('إغلاق البحث', 'Close command palette'),
        onclick: closeCommandPalette
      },
      '✕'
    );
    var body = safeEl('div', { id: 'hunterCmdResults', class: 'hp-palette-body', role: 'listbox' });
    var countLabel = safeEl('span', { id: 'hunterCmdStatus' }, tr('اكتب للبحث في جميع وحدات المنصة', 'Type to search across all subsystems'));
    var foot = safeEl('div', { class: 'hp-palette-foot' }, [
      countLabel,
      safeEl('div', { style: 'display:flex;gap:8px;align-items:center;' }, [
        safeEl('span', { class: 'hp-kbd ltr-isolate' }, '↑↓'),
        safeEl('span', { class: 'hp-kbd ltr-isolate' }, 'Enter'),
        safeEl('span', { class: 'hp-kbd ltr-isolate' }, 'Esc')
      ])
    ]);

    var dialog = safeEl(
      'div',
      {
        class: 'hp-palette-dialog',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-labelledby': 'hunterCmdTitle'
      },
      [
        safeEl('span', { id: 'hunterCmdTitle', class: 'sr-only' }, tr('لوحة الأوامر والبحث الشامل', 'Command Palette & Global Search')),
        safeEl('div', { class: 'hp-palette-head' }, [input, closeBtn]),
        body,
        foot
      ]
    );

    var backdrop = safeEl(
      'div',
      {
        id: 'hunterCommandPalette',
        class: 'hp-palette-backdrop',
        onclick: function (ev) {
          if (ev.target === backdrop) closeCommandPalette();
        }
      },
      dialog
    );

    input.addEventListener('input', function () {
      var val = input.value;
      if (_searchDebounce) clearTimeout(_searchDebounce);
      _searchDebounce = setTimeout(function () {
        runPaletteSearch(val);
      }, 160);
    });

    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        closeCommandPalette();
      } else if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        if (_paletteItems.length) {
          _selectedIndex = (_selectedIndex + 1) % _paletteItems.length;
          highlightPaletteItem();
        }
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        if (_paletteItems.length) {
          _selectedIndex = (_selectedIndex - 1 + _paletteItems.length) % _paletteItems.length;
          highlightPaletteItem();
        }
      } else if (ev.key === 'Enter') {
        ev.preventDefault();
        activatePaletteItem(_selectedIndex);
      }
    });

    document.body.appendChild(backdrop);
    _paletteEls = { backdrop: backdrop, input: input, body: body, status: countLabel };
    return _paletteEls;
  }

  function highlightPaletteItem() {
    if (!_paletteEls) return;
    var nodes = _paletteEls.body.querySelectorAll('.hp-palette-item');
    for (var i = 0; i < nodes.length; i += 1) {
      var active = i === _selectedIndex;
      nodes[i].classList.toggle('is-selected', active);
      nodes[i].setAttribute('aria-selected', active ? 'true' : 'false');
      if (active && typeof nodes[i].scrollIntoView === 'function') {
        nodes[i].scrollIntoView({ block: 'nearest' });
      }
    }
  }

  function activatePaletteItem(index) {
    var item = _paletteItems[index];
    if (!item) return;
    closeCommandPalette();
    if (typeof item.run === 'function') {
      item.run();
      return;
    }
    navigate(item.ref || item);
  }

  function renderPaletteGroups(groups, query) {
    if (!_paletteEls) return;
    var body = _paletteEls.body;
    body.textContent = '';
    _paletteItems = [];
    _selectedIndex = 0;

    var groupOrder = [
      ['actions', tr('إجراءات سريعة', 'Quick Actions')],
      ['engagements', tr('الأهداف والارتباطات', 'Engagements')],
      ['runs', tr('التشغيلات والمهام', 'Runs')],
      ['findings', tr('الثغرات والتقارير', 'Findings')],
      ['assets', tr('الأصول ونقاط النهاية', 'Assets')],
      ['leads', tr('لوحة الخيوط', 'Leads')],
      ['conversations', tr('محادثات المساعد الذكي', 'Copilot Conversations')],
      ['tools', tr('الأدوات', 'Tools')],
      ['central_skills', tr('المهارات', 'Skills')]
    ];

    groupOrder.forEach(function (pair) {
      var key = pair[0];
      var title = pair[1];
      var list = groups[key];
      if (!Array.isArray(list) || list.length === 0) return;

      body.appendChild(safeEl('div', { class: 'hp-palette-group-title' }, title));
      list.forEach(function (item) {
        var idx = _paletteItems.length;
        _paletteItems.push(item);
        var btn = safeEl(
          'button',
          {
            type: 'button',
            class: 'hp-palette-item' + (idx === 0 ? ' is-selected' : ''),
            role: 'option',
            'aria-selected': idx === 0 ? 'true' : 'false',
            onclick: function () {
              activatePaletteItem(idx);
            }
          },
          [
            safeEl('div', { class: 'hp-palette-item-main' }, [
              safeEl('div', { class: 'hp-palette-item-title' }, item.title || item.id || ''),
              item.subtitle ? safeEl('div', { class: 'hp-palette-item-sub ltr-isolate' }, item.subtitle) : null
            ]),
            safeEl('span', { class: 'hp-palette-kind' }, item.kind || key)
          ]
        );
        body.appendChild(btn);
      });
    });

    if (_paletteItems.length === 0) {
      body.appendChild(
        safeEl(
          'div',
          { style: 'padding:24px;text-align:center;color:var(--text-muted);font-size:0.875rem;' },
          query
            ? tr('لا توجد نتائج مطابقة في المنصة.', 'No matching records across engagements, runs, findings, or tools.')
            : tr('لا توجد إجراءات.', 'No actions available.')
        )
      );
    }

    _paletteEls.status.textContent = query
      ? tr('النتائج: ', 'Results: ') + _paletteItems.length
      : tr('الأوامر المتاحة: ', 'Available actions: ') + _paletteItems.length;
  }

  async function runPaletteSearch(query) {
    var q = (query || '').trim();
    var actions = buildQuickActions();
    if (!q) {
      renderPaletteGroups({ actions: actions }, '');
      return;
    }
    var ql = q.toLowerCase();
    var matchedActions = actions.filter(function (a) {
      return a.title.toLowerCase().indexOf(ql) !== -1 || a.subtitle.toLowerCase().indexOf(ql) !== -1;
    });

    try {
      if (_paletteEls) {
        _paletteEls.status.textContent = tr('جارِ البحث...', 'Searching...');
      }
      var data = await search(q, 30);
      if (!_paletteOpen || (_paletteEls && _paletteEls.input.value.trim() !== q)) return;
      var groups = Object.assign({ actions: matchedActions.slice(0, 4) }, data.groups || {});
      renderPaletteGroups(groups, q);
    } catch (_err) {
      renderPaletteGroups({ actions: matchedActions }, q);
    }
  }

  function openCommandPalette(initialQuery) {
    var els = ensurePalette();
    if (!els) return;
    _previousFocus = document.activeElement;
    _paletteOpen = true;
    els.input.placeholder = tr(
      'ابحث عن هدف، مهمة، ثغرة، خيط، أداة، مهارة، أو أمر...',
      'Search engagements, runs, findings, assets, leads, tools, skills...'
    );
    els.input.value = typeof initialQuery === 'string' ? initialQuery : '';
    els.backdrop.classList.add('is-open');
    runPaletteSearch(els.input.value);
    setTimeout(function () {
      els.input.focus();
      els.input.select();
    }, 10);
  }

  function closeCommandPalette() {
    if (!_paletteEls) return;
    _paletteOpen = false;
    _paletteEls.backdrop.classList.remove('is-open');
    if (_previousFocus && typeof _previousFocus.focus === 'function') {
      try {
        _previousFocus.focus();
      } catch (_e) {
        /* ignore */
      }
    }
    _previousFocus = null;
  }

  /* ── Global Shortcuts & Lifecycle Wiring ───────────────────────────────── */

  function bindGlobalListeners() {
    if (typeof document === 'undefined' || bindGlobalListeners._bound) return;
    bindGlobalListeners._bound = true;

    document.addEventListener('keydown', function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && ev.key.toLowerCase() === 'k') {
        ev.preventDefault();
        if (_paletteOpen) closeCommandPalette();
        else openCommandPalette('');
      }
    });

    document.addEventListener('click', function (ev) {
      var trigger = ev.target && ev.target.closest ? ev.target.closest('[data-hunter-search-trigger]') : null;
      if (trigger) {
        ev.preventDefault();
        openCommandPalette('');
      }
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        disconnectStream();
      } else if (_streamStarted) {
        scheduleRefresh(100);
        connectStream();
      }
    });

    if (typeof window !== 'undefined') {
      window.addEventListener('pagehide', disconnectStream);
    }
  }

  function init() {
    if (_streamStarted) return Promise.resolve(getState());
    _streamStarted = true;
    bindGlobalListeners();
    ensureStyles();
    return refreshOverview().finally(function () {
      connectStream();
    });
  }

  var subscribers = [];
  function subscribe(fn) {
    if (typeof fn !== 'function') return function () {};
    subscribers.push(fn);
    var handler = function (ev) { fn(ev.detail); };
    if (typeof window !== 'undefined') window.addEventListener('hunter:state', handler);
    if (state.initialized) fn(getState());
    return function () {
      if (typeof window !== 'undefined') window.removeEventListener('hunter:state', handler);
    };
  }

  var HunterPlatform = {
    version: '1.0.0',
    init: init,
    getState: getState,
    subscribe: subscribe,
    refreshOverview: refreshOverview,
    refreshEngagements: refreshEngagements,
    setContext: setContext,
    selectEngagement: selectEngagement,
    createEngagement: createEngagement,
    getActiveEngagement: getActiveEngagement,
    getActiveRun: getActiveRun,
    startRun: startRun,
    pauseRun: pauseRun,
    resumeRun: resumeRun,
    stopRun: stopRun,
    decideApproval: decideApproval,
    markNotificationRead: markNotificationRead,
    search: search,
    artexRequest: artexRequest,
    navigate: navigate,
    openCommandPalette: openCommandPalette,
    closeCommandPalette: closeCommandPalette,
    buildQueryPreserveParams: buildQueryPreserveParams,
    notify: notify
  };

  global.HunterPlatform = HunterPlatform;

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () {
        init();
      });
    } else {
      init();
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = HunterPlatform;
  }
})(typeof window !== 'undefined' ? window : globalThis);
