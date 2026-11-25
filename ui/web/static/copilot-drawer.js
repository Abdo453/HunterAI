/* ==========================================================================
   HunterAI Persistent Grounded Copilot Drawer (window.HunterCopilot)
   - Auto-mounts collapsible, resizable side drawer on #hunterCopilotMount or body
   - Works identically across index.html and opencode.html (Ctrl+J toggle)
   - Multi-conversation persistence (/api/copilot/conversations)
   - Chunked UTF-8 ReadableStream SSE parser (/api/copilot/chat/stream)
   - Markdown + DOMPurify (.ltr-isolate code blocks), clickable citations,
     inline Approval Gate cards, file attachments, and non-disruptive live run pills
   ========================================================================== */
(function (global) {
  'use strict';

  var Core = global.HunterCore || null;
  var WIDTH_KEY = 'hunterai_copilot_width';
  var OPEN_KEY = 'hunterai_copilot_open';
  var MIN_WIDTH = 320;
  var MAX_WIDTH = 780;

  var MODES = [
    { value: 'analyst', ar: 'محلل أمني (Analyst)', en: 'Security Analyst' },
    { value: 'redteam', ar: 'مشغّل Red Team', en: 'Red Team Operator' },
    { value: 'passive', ar: 'تحليل سلبي (Passive)', en: 'Passive Read-Only' },
    { value: 'recon', ar: 'استطلاع وسطوح الهجوم', en: 'Recon & Surface' },
    { value: 'triage', ar: 'فرز الأدلة والنتائج', en: 'Findings Triage' }
  ];

  var copilotState = {
    open: false,
    expanded: false,
    width: 440,
    conversations: [],
    activeConversationId: null,
    messages: [],
    models: [],
    selectedModel: 'auto',
    selectedMode: 'analyst',
    attachments: [],
    streaming: false,
    streamAbortController: null,
    renaming: false,
    confirmDeleteId: null
  };

  var _boundWorkspaces = [];
  var _drawerEls = null;
  var _catalogLoaded = false;

  /* ── Helpers ───────────────────────────────────────────────────────────── */

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

  function esc(val) {
    if (Core && typeof Core.escapeHtml === 'function') return Core.escapeHtml(val);
    if (val === null || val === undefined) return '';
    return String(val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function el(tag, attrs, children) {
    if (Core && typeof Core.el === 'function') return Core.el(tag, attrs, children);
    var node = document.createElement(tag);
    if (attrs && typeof attrs === 'object') {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined) return;
        if (k === 'class' || k === 'className') node.className = String(v);
        else if (k === 'text' || k === 'textContent') node.textContent = String(v);
        else if (k.indexOf('on') === 0 && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
        else node.setAttribute(k, String(v));
      });
    }
    if (children !== undefined && children !== null) {
      var arr = Array.isArray(children) ? children : [children];
      arr.forEach(function (c) {
        if (c === null || c === undefined || c === false || c === true) return;
        if (typeof Node !== 'undefined' && c instanceof Node) node.appendChild(c);
        else node.appendChild(document.createTextNode(String(c)));
      });
    }
    return node;
  }

  function sanitize(html) {
    if (Core && typeof Core.sanitizeHtml === 'function') return Core.sanitizeHtml(html);
    if (global.DOMPurify && typeof global.DOMPurify.sanitize === 'function') {
      return global.DOMPurify.sanitize(String(html || ''));
    }
    return esc(html);
  }

  function toast(msg, type) {
    if (Core && typeof Core.toast === 'function') Core.toast(msg, type || 'info');
  }

  function safeReadStorage(key, fallback) {
    try {
      var v = global.localStorage ? global.localStorage.getItem(key) : null;
      return v !== null ? v : fallback;
    } catch (_e) {
      return fallback;
    }
  }

  function safeWriteStorage(key, value) {
    try {
      if (global.localStorage) global.localStorage.setItem(key, String(value));
    } catch (_e) {
      /* ignore */
    }
  }

  /* ── Safe Markdown Renderer (.ltr-isolate on code blocks) ──────────────── */

  function renderInlineMd(text) {
    var s = esc(text);
    s = s.replace(/`([^`\n]+)`/g, '<code class="hc-inline-code ltr-isolate" dir="ltr">$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, function (_m, label, url) {
      var safeUrl = Core && typeof Core.safeHref === 'function' ? Core.safeHref(url, '#') : url;
      return '<a href="' + esc(safeUrl) + '" target="_blank" rel="noopener noreferrer">' + label + '</a>';
    });
    return s;
  }

  function markdownToSafeHtml(src) {
    var lines = String(src || '').replace(/\r\n/g, '\n').split('\n');
    var out = [];
    var inCode = false;
    var codeLang = '';
    var codeBuf = [];
    var inList = false;

    function closeList() {
      if (inList) {
        out.push('</ul>');
        inList = false;
      }
    }

    function flushCode() {
      var langBadge = codeLang ? '<div class="hc-code-lang ltr-isolate" dir="ltr">' + esc(codeLang) + '</div>' : '';
      out.push(
        '<div class="hc-code-wrap ltr-isolate" dir="ltr">' +
          langBadge +
          '<pre class="hc-pre ltr-isolate" dir="ltr"><code>' +
          codeBuf.join('\n') +
          '</code></pre></div>'
      );
      codeBuf = [];
      codeLang = '';
      inCode = false;
    }

    for (var i = 0; i < lines.length; i += 1) {
      var raw = lines[i];
      var fence = raw.match(/^```\s*([A-Za-z0-9_.-]*)/);
      if (fence) {
        if (inCode) {
          flushCode();
        } else {
          closeList();
          inCode = true;
          codeLang = fence[1] || '';
        }
        continue;
      }
      if (inCode) {
        codeBuf.push(esc(raw));
        continue;
      }
      var listMatch = raw.match(/^\s*[-*]\s+(.*)$/);
      if (listMatch) {
        if (!inList) {
          out.push('<ul>');
          inList = true;
        }
        out.push('<li>' + renderInlineMd(listMatch[1]) + '</li>');
        continue;
      }
      closeList();
      if (!raw.trim()) continue;
      var heading = raw.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        var lvl = Math.min(4, Math.max(2, heading[1].length + 1));
        out.push('<h' + lvl + ' class="hc-md-h">' + renderInlineMd(heading[2]) + '</h' + lvl + '>');
        continue;
      }
      if (raw.indexOf('> ') === 0) {
        out.push('<blockquote>' + renderInlineMd(raw.slice(2)) + '</blockquote>');
        continue;
      }
      out.push('<p>' + renderInlineMd(raw) + '</p>');
    }
    if (inCode) flushCode();
    closeList();
    return sanitize(out.join('') || '<p></p>');
  }

  function enhanceCodeBlocks(container) {
    if (!container) return;
    var wraps = container.querySelectorAll('.hc-code-wrap');
    for (var i = 0; i < wraps.length; i += 1) {
      var wrap = wraps[i];
      wrap.classList.add('ltr-isolate');
      wrap.setAttribute('dir', 'ltr');
      if (wrap.querySelector('.hc-code-copy')) continue;
      var pre = wrap.querySelector('pre');
      if (!pre) continue;
      pre.classList.add('ltr-isolate');
      pre.setAttribute('dir', 'ltr');
      (function (preNode, wrapNode) {
        var btn = el(
          'button',
          {
            type: 'button',
            class: 'hc-code-copy',
            'aria-label': tr('نسخ الكود', 'Copy code'),
            onclick: function () {
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(preNode.textContent || '');
              }
              btn.textContent = tr('تم النسخ', 'Copied');
              setTimeout(function () {
                btn.textContent = tr('نسخ', 'Copy');
              }, 1400);
            }
          },
          tr('نسخ', 'Copy')
        );
        wrapNode.appendChild(btn);
      })(pre, wrap);
    }
  }

  /* ── Styles ────────────────────────────────────────────────────────────── */

  function ensureStyles() {
    if (typeof document === 'undefined' || document.getElementById('hunter-copilot-styles')) return;
    var css = [
      '.hc-drawer{position:fixed;top:0;bottom:0;inset-inline-end:0;z-index:8800;width:var(--hc-width,440px);max-width:96vw;background:var(--bg-surface,#111827);color:var(--text-primary,#f8fafc);border-inline-start:1px solid var(--border-strong,#475569);box-shadow:var(--shadow-md,0 8px 28px rgba(0,0,0,0.45));display:none;flex-direction:column;font-family:var(--font-sans,sans-serif);}',
      '.hc-drawer.is-open{display:flex;}',
      '.hc-drawer.is-expanded{width:100vw !important;max-width:100vw;border-inline-start:none;}',
      '.hc-resizer{position:absolute;top:0;bottom:0;inset-inline-start:-4px;width:8px;cursor:col-resize;z-index:2;user-select:none;display:flex;align-items:center;justify-content:center;}',
      '.hc-resizer::after{content:"";width:2px;height:44px;border-radius:2px;background:var(--border-strong,#475569);opacity:0.45;}',
      '.hc-resizer:hover::after,.hc-resizer:focus-visible::after{opacity:1;background:var(--accent-primary,#38bdf8);}',
      '.hc-drawer.is-expanded .hc-resizer{display:none;}',
      '.hc-header{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 12px;border-bottom:1px solid var(--border-subtle,#1f2937);background:var(--bg-elevated,#1a2332);}',
      '.hc-title-wrap{display:flex;align-items:center;gap:8px;min-width:0;}',
      '.hc-title{font-size:0.9375rem;font-weight:700;margin:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}',
      '.hc-header-actions{display:flex;align-items:center;gap:6px;}',
      '.hc-icon-btn{min-width:36px;min-height:36px;padding:0 8px;border-radius:var(--radius-md,8px);border:1px solid var(--border-subtle,#1f2937);background:var(--bg-surface,#111827);color:var(--text-secondary,#cbd5e1);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:4px;font-size:0.78rem;font-family:inherit;}',
      '.hc-icon-btn:hover{border-color:var(--accent-primary,#38bdf8);color:var(--text-primary,#f8fafc);}',
      '.hc-runs-strip{display:flex;align-items:center;gap:6px;padding:6px 12px;border-bottom:1px solid var(--border-subtle,#1f2937);background:var(--bg-inset,#070a10);overflow-x:auto;flex-shrink:0;}',
      '.hc-run-pill{font-size:0.72rem;font-family:var(--font-mono,monospace);padding:3px 9px;border-radius:999px;border:1px solid var(--border-subtle,#1f2937);background:var(--bg-elevated,#1a2332);color:var(--text-secondary,#cbd5e1);white-space:nowrap;cursor:pointer;display:inline-flex;align-items:center;gap:6px;}',
      '.hc-run-pill.is-active{border-color:var(--accent-success,#34d399);color:var(--accent-success,#34d399);background:var(--accent-success-bg,rgba(52,211,153,0.14));}',
      '.hc-controls{display:flex;flex-direction:column;gap:8px;padding:8px 12px;border-bottom:1px solid var(--border-subtle,#1f2937);background:var(--bg-surface,#111827);flex-shrink:0;}',
      '.hc-ctrl-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;}',
      '.hc-select,.hc-input{min-height:36px;background:var(--bg-inset,#070a10);color:var(--text-primary,#f8fafc);border:1px solid var(--border-subtle,#1f2937);border-radius:var(--radius-sm,4px);padding:4px 8px;font-size:0.8rem;font-family:inherit;}',
      '.hc-select{flex:1;min-width:120px;}',
      '.hc-inline-confirm{display:flex;align-items:center;gap:6px;padding:6px 8px;background:var(--bg-elevated,#1a2332);border:1px solid var(--border-strong,#475569);border-radius:var(--radius-sm,4px);font-size:0.78rem;}',
      '.hc-messages{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:12px;background:var(--bg-canvas,#0b0f17);}',
      '.hc-empty{margin:auto;text-align:center;max-width:340px;color:var(--text-muted,#94a3b8);display:flex;flex-direction:column;gap:10px;padding:16px;}',
      '.hc-empty-title{font-size:1rem;font-weight:700;color:var(--text-primary,#f8fafc);}',
      '.hc-msg{display:flex;flex-direction:column;gap:6px;padding:10px 12px;border-radius:var(--radius-md,8px);border:1px solid var(--border-subtle,#1f2937);background:var(--bg-surface,#111827);}',
      '.hc-msg.user{background:var(--bg-elevated,#1a2332);border-inline-start:3px solid var(--accent-primary,#38bdf8);}',
      '.hc-msg.assistant{border-inline-start:3px solid var(--accent-ai,#a78bfa);}',
      '.hc-msg-head{display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:0.72rem;color:var(--text-muted,#94a3b8);font-family:var(--font-mono,monospace);}',
      '.hc-msg-body{font-size:0.875rem;line-height:1.58;word-break:break-word;}',
      '.hc-msg-body p{margin:0 0 8px;}.hc-msg-body p:last-child{margin-bottom:0;}',
      '.hc-msg-body ul{margin:0 0 8px;padding-inline-start:20px;}',
      '.hc-msg-body blockquote{margin:6px 0;padding:4px 10px;border-inline-start:3px solid var(--border-strong,#475569);color:var(--text-secondary,#cbd5e1);}',
      '.hc-md-h{margin:8px 0 4px;font-size:0.9rem;color:var(--text-primary,#f8fafc);}',
      '.hc-inline-code{background:var(--bg-inset,#070a10);border:1px solid var(--border-subtle,#1f2937);padding:1px 5px;border-radius:4px;font-family:var(--font-mono,monospace);font-size:0.82em;}',
      '.hc-code-wrap{position:relative;margin:8px 0;background:var(--bg-inset,#070a10);border:1px solid var(--border-subtle,#1f2937);border-radius:var(--radius-sm,4px);overflow:hidden;}',
      '.hc-code-lang{font-size:0.68rem;font-family:var(--font-mono,monospace);color:var(--text-muted,#94a3b8);padding:4px 10px;border-bottom:1px solid var(--border-subtle,#1f2937);background:var(--bg-elevated,#1a2332);}',
      '.hc-pre{margin:0;padding:10px;overflow-x:auto;font-family:var(--font-mono,monospace);font-size:0.78rem;line-height:1.45;color:var(--text-primary,#f8fafc);}',
      '.hc-code-copy{position:absolute;top:4px;right:6px;min-height:26px;padding:2px 8px;font-size:0.7rem;border:1px solid var(--border-subtle,#1f2937);border-radius:4px;background:var(--bg-surface,#111827);color:var(--text-secondary,#cbd5e1);cursor:pointer;}',
      '.hc-code-copy:hover{border-color:var(--accent-primary,#38bdf8);color:var(--text-primary,#f8fafc);}',
      '.hc-badge{display:inline-flex;align-items:center;gap:4px;font-size:0.6875rem;padding:2px 7px;border-radius:999px;font-family:var(--font-mono,monospace);border:1px solid var(--border-subtle,#1f2937);}',
      '.hc-badge-warn{background:var(--accent-warning-bg,rgba(251,191,36,0.14));color:var(--accent-warning,#fbbf24);border-color:var(--accent-warning,#fbbf24);}',
      '.hc-badge-danger{background:var(--accent-danger-bg,rgba(251,113,133,0.14));color:var(--accent-danger,#fb7185);border-color:var(--accent-danger,#fb7185);}',
      '.hc-badge-info{background:var(--accent-primary-bg,rgba(56,189,248,0.14));color:var(--accent-primary,#38bdf8);}',
      '.hc-refs{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;}',
      '.hc-ref-chip{min-height:30px;padding:3px 9px;font-size:0.74rem;border-radius:999px;border:1px solid var(--border-subtle,#1f2937);background:var(--bg-elevated,#1a2332);color:var(--accent-primary,#38bdf8);cursor:pointer;display:inline-flex;align-items:center;gap:5px;font-family:inherit;}',
      '.hc-ref-chip:hover{border-color:var(--accent-primary,#38bdf8);background:var(--accent-primary-bg,rgba(56,189,248,0.14));}',
      '.hc-approval-card{margin-top:8px;padding:10px;border-radius:var(--radius-md,8px);border:1px solid var(--accent-warning,#fbbf24);background:var(--accent-warning-bg,rgba(251,191,36,0.1));display:flex;flex-direction:column;gap:8px;font-size:0.8rem;}',
      '.hc-approval-card.is-decided{border-color:var(--border-strong,#475569);background:var(--bg-elevated,#1a2332);}',
      '.hc-approval-actions{display:flex;gap:6px;flex-wrap:wrap;align-items:center;}',
      '.hc-btn{min-height:36px;padding:5px 12px;border-radius:var(--radius-sm,4px);border:1px solid var(--border-strong,#475569);background:var(--bg-elevated,#1a2332);color:var(--text-primary,#f8fafc);cursor:pointer;font-size:0.8rem;font-weight:600;font-family:inherit;}',
      '.hc-btn.primary{background:var(--accent-primary,#38bdf8);color:var(--on-accent,#070a10);border-color:var(--accent-primary,#38bdf8);}',
      '.hc-btn.success{background:var(--accent-success,#34d399);color:var(--on-accent,#070a10);border-color:var(--accent-success,#34d399);}',
      '.hc-btn.danger{background:var(--accent-danger,#fb7185);color:var(--on-accent,#070a10);border-color:var(--accent-danger,#fb7185);}',
      '.hc-btn:disabled{opacity:0.55;cursor:not-allowed;}',
      '.hc-composer{padding:10px 12px;border-top:1px solid var(--border-subtle,#1f2937);background:var(--bg-elevated,#1a2332);display:flex;flex-direction:column;gap:8px;flex-shrink:0;}',
      '.hc-attach-list{display:flex;flex-wrap:wrap;gap:6px;}',
      '.hc-attach-chip{font-size:0.74rem;padding:2px 8px;border-radius:999px;background:var(--bg-surface,#111827);border:1px solid var(--border-strong,#475569);display:inline-flex;align-items:center;gap:6px;}',
      '.hc-composer-row{display:flex;gap:8px;align-items:flex-end;}',
      '.hc-textarea{flex:1;min-height:44px;max-height:140px;resize:vertical;padding:8px 10px;border-radius:var(--radius-md,8px);border:1px solid var(--border-strong,#475569);background:var(--bg-inset,#070a10);color:var(--text-primary,#f8fafc);font-family:inherit;font-size:0.875rem;line-height:1.45;}',
      '.hc-workspace-shell{display:flex;flex-direction:column;height:100%;min-height:560px;background:var(--bg-surface,#111827);border:1px solid var(--border-subtle,#1f2937);border-radius:var(--radius-md,8px);overflow:hidden;}'
    ].join('\n');
    var style = document.createElement('style');
    style.id = 'hunter-copilot-styles';
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }

  /* ── API Calls ─────────────────────────────────────────────────────────── */

  async function apiJson(url, opts) {
    var res = await fetch(url, opts || {});
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      throw new Error(data.detail || data.error || ('HTTP ' + res.status));
    }
    return data;
  }

  async function loadModelsCatalog() {
    if (_catalogLoaded && copilotState.models.length > 0) return copilotState.models;
    try {
      var cat = await apiJson('/api/models/catalog');
      var list = [{ id: 'auto', label: tr('تلقائي (الموجه الذكي)', 'Auto (Smart Router)') }];
      (cat.choices || []).forEach(function (ch) {
        list.push({
          id: ch.id,
          label: (ch.kind === 'local' ? 'Local · ' : 'Cloud · ') + (ch.model || ch.id)
        });
      });
      copilotState.models = list;
      _catalogLoaded = true;
    } catch (_e) {
      if (copilotState.models.length === 0) {
        copilotState.models = [{ id: 'auto', label: 'Auto (Smart Router)' }];
      }
    }
    syncAllViews();
    return copilotState.models;
  }

  async function refreshConversations() {
    try {
      var data = await apiJson('/api/copilot/conversations');
      copilotState.conversations = Array.isArray(data.conversations) ? data.conversations : [];
      var ctxId = global.HunterPlatform && global.HunterPlatform.getState().context.active_conversation_id;
      if (!copilotState.activeConversationId && ctxId) {
        copilotState.activeConversationId = ctxId;
      }
      if (copilotState.activeConversationId) {
        var exists = copilotState.conversations.some(function (c) {
          return c.conversation_id === copilotState.activeConversationId;
        });
        if (!exists) copilotState.activeConversationId = null;
      }
      if (!copilotState.activeConversationId && copilotState.conversations.length > 0) {
        await selectConversation(copilotState.conversations[0].conversation_id);
        return;
      }
      syncAllViews();
    } catch (_err) {
      syncAllViews();
    }
  }

  async function createConversation(title) {
    var eng = global.HunterPlatform ? global.HunterPlatform.getActiveEngagement() : null;
    var run = global.HunterPlatform ? global.HunterPlatform.getActiveRun() : null;
    var data = await apiJson('/api/copilot/conversations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: title || tr('تحقيق أمني جديد', 'New Investigation'),
        engagement_id: eng ? eng.engagement_id : null,
        run_id: run ? run.run_id : null,
        mode: copilotState.selectedMode || 'analyst',
        model: copilotState.selectedModel || 'auto',
        set_active: true
      })
    });
    if (data.conversation) {
      copilotState.activeConversationId = data.conversation.conversation_id;
      copilotState.messages = [];
      copilotState.conversations.unshift(data.conversation);
      if (global.HunterPlatform) {
        global.HunterPlatform.setContext({ active_conversation_id: data.conversation.conversation_id }).catch(function () {});
      }
      syncAllViews();
    }
    return data.conversation;
  }

  async function selectConversation(cid) {
    if (!cid) return;
    try {
      var detail = await apiJson('/api/copilot/conversations/' + encodeURIComponent(cid));
      copilotState.activeConversationId = cid;
      if (detail.conversation) {
        copilotState.selectedMode = detail.conversation.mode || copilotState.selectedMode;
        copilotState.selectedModel = detail.conversation.model || copilotState.selectedModel;
      }
      copilotState.messages = Array.isArray(detail.messages) ? detail.messages : [];
      if (global.HunterPlatform) {
        global.HunterPlatform.setContext({ active_conversation_id: cid }).catch(function () {});
      }
      syncAllViews();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function renameConversation(cid, newTitle) {
    var clean = (newTitle || '').trim();
    if (!cid || !clean) return;
    var data = await apiJson('/api/copilot/conversations/' + encodeURIComponent(cid), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: clean })
    });
    if (data.conversation) {
      copilotState.conversations = copilotState.conversations.map(function (c) {
        return c.conversation_id === cid ? data.conversation : c;
      });
      copilotState.renaming = false;
      syncAllViews();
      toast(tr('تم تحديث اسم المحادثة', 'Conversation renamed'), 'success');
    }
  }

  async function deleteConversation(cid) {
    if (!cid) return;
    await apiJson('/api/copilot/conversations/' + encodeURIComponent(cid), { method: 'DELETE' });
    copilotState.conversations = copilotState.conversations.filter(function (c) {
      return c.conversation_id !== cid;
    });
    copilotState.confirmDeleteId = null;
    if (copilotState.activeConversationId === cid) {
      copilotState.activeConversationId = copilotState.conversations[0] ? copilotState.conversations[0].conversation_id : null;
      copilotState.messages = [];
      if (copilotState.activeConversationId) {
        await selectConversation(copilotState.activeConversationId);
        return;
      }
    }
    syncAllViews();
    toast(tr('تم حذف المحادثة', 'Conversation deleted'), 'info');
  }

  async function uploadAttachment(file) {
    if (!file) return null;
    var fd = new FormData();
    fd.append('file', file);
    if (copilotState.activeConversationId) {
      fd.append('conversation_id', copilotState.activeConversationId);
    }
    var data = await apiJson('/api/copilot/attachments', {
      method: 'POST',
      body: fd
    });
    if (data.attachment) {
      copilotState.attachments.push(data.attachment);
      syncAllViews();
      toast(tr('تم إرفاق الملف: ', 'Attached: ') + data.attachment.filename, 'success');
    }
    return data.attachment;
  }

  /* ── Chunked UTF-8 ReadableStream SSE Chat Streamer ────────────────────── */

  async function sendMessage(rawText, options) {
    var opts = options || {};
    var text = (rawText || '').trim();
    if (!text || copilotState.streaming) return null;

    if (!copilotState.activeConversationId) {
      await createConversation(text.slice(0, 56));
    }

    var cid = copilotState.activeConversationId;
    var eng = global.HunterPlatform ? global.HunterPlatform.getActiveEngagement() : null;
    var run = global.HunterPlatform ? global.HunterPlatform.getActiveRun() : null;
    var attachIds = copilotState.attachments.map(function (a) { return a.attachment_id; });

    var userMsg = {
      message_id: 'tmp_u_' + Date.now(),
      role: 'user',
      content: text,
      created_at: Date.now() / 1000
    };
    var assistantMsg = {
      message_id: 'tmp_a_' + Date.now(),
      role: 'assistant',
      content: '',
      pending: true,
      refs: [],
      citations: [],
      approval: null,
      policy_blocked: null,
      metadata: { model: copilotState.selectedModel, fallback: false }
    };

    copilotState.messages.push(userMsg, assistantMsg);
    copilotState.attachments = [];
    copilotState.streaming = true;
    var controller = new AbortController();
    copilotState.streamAbortController = controller;
    syncAllViews();
    scrollMessagesToBottom();

    try {
      var res = await fetch('/api/copilot/chat/stream', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream'
        },
        body: JSON.stringify({
          message: text,
          conversation_id: cid,
          engagement_id: opts.engagement_id || (eng ? eng.engagement_id : null),
          run_id: opts.run_id || (run ? run.run_id : null),
          model: opts.model || copilotState.selectedModel || 'auto',
          mode: opts.mode || copilotState.selectedMode || 'analyst',
          attachment_ids: attachIds
        }),
        signal: controller.signal
      });
      if (!res.ok || !res.body) {
        throw new Error('Copilot stream failed: HTTP ' + res.status);
      }

      var reader = res.body.getReader();
      var decoder = new TextDecoder('utf-8');
      var buffer = '';
      var evName = 'message';
      var dataLines = [];

      function handleSseEvent(name, jsonStr) {
        if (!jsonStr) return;
        var payload = null;
        try {
          payload = JSON.parse(jsonStr);
        } catch (_e) {
          return;
        }
        if (name === 'start') {
          if (payload.conversation_id) {
            copilotState.activeConversationId = payload.conversation_id;
          }
          if (payload.assistant_message_id) {
            assistantMsg.message_id = payload.assistant_message_id;
          }
        } else if (name === 'context') {
          if (Array.isArray(payload.refs)) assistantMsg.refs = payload.refs;
          if (Array.isArray(payload.citations)) assistantMsg.citations = payload.citations;
          updateMessageNode(assistantMsg);
        } else if (name === 'approval_request') {
          if (payload.approval) {
            assistantMsg.approval = payload.approval;
            assistantMsg.approval_id = payload.approval.approval_id;
            updateMessageNode(assistantMsg);
          }
          if (global.HunterPlatform) global.HunterPlatform.refreshOverview();
        } else if (name === 'policy_blocked') {
          assistantMsg.policy_blocked = payload.policy || payload;
          updateMessageNode(assistantMsg);
        } else if (name === 'token') {
          assistantMsg.content += payload.delta || '';
          if (payload.fallback) {
            assistantMsg.metadata = Object.assign({}, assistantMsg.metadata, { fallback: true });
          }
          updateMessageNode(assistantMsg);
          scrollMessagesToBottom();
        } else if (name === 'refs') {
          if (Array.isArray(payload.refs)) assistantMsg.refs = payload.refs;
          if (Array.isArray(payload.citations)) assistantMsg.citations = payload.citations;
          updateMessageNode(assistantMsg);
        } else if (name === 'done') {
          assistantMsg.pending = false;
          if (payload.answer && !assistantMsg.content) assistantMsg.content = payload.answer;
          assistantMsg.model = payload.model_used || assistantMsg.model;
          assistantMsg.metadata = Object.assign({}, assistantMsg.metadata, {
            provider: payload.provider,
            fallback: Boolean(payload.fallback)
          });
          if (Array.isArray(payload.refs)) assistantMsg.refs = payload.refs;
          if (Array.isArray(payload.citations)) assistantMsg.citations = payload.citations;
          if (payload.approval) assistantMsg.approval = payload.approval;
          if (payload.policy && !payload.policy.allowed) assistantMsg.policy_blocked = payload.policy;
          updateMessageNode(assistantMsg);
        } else if (name === 'error') {
          assistantMsg.pending = false;
          assistantMsg.content += (assistantMsg.content ? '\n\n' : '') + '⚠️ ' + (payload.error || 'Stream error');
          updateMessageNode(assistantMsg);
        }
      }

      function flushFrame() {
        if (dataLines.length > 0) {
          handleSseEvent(evName, dataLines.join('\n'));
        }
        evName = 'message';
        dataLines = [];
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
          var ln = lines[i];
          if (ln === '') {
            flushFrame();
          } else if (ln.charAt(0) === ':') {
            /* heartbeat */
          } else if (ln.indexOf('event:') === 0) {
            evName = ln.slice(6).trim() || 'message';
          } else if (ln.indexOf('data:') === 0) {
            dataLines.push(ln.slice(5).replace(/^ /, ''));
          }
        }
      }
      if (buffer.trim() && buffer.indexOf('data:') === 0) {
        dataLines.push(buffer.slice(5).replace(/^ /, ''));
      }
      flushFrame();
      assistantMsg.pending = false;
    } catch (err) {
      assistantMsg.pending = false;
      if (err && err.name === 'AbortError') {
        assistantMsg.content += (assistantMsg.content ? '\n' : '') + '[' + tr('تم إيقاف البث', 'Stream stopped') + ']';
      } else {
        assistantMsg.content += (assistantMsg.content ? '\n' : '') + '⚠️ ' + (err && err.message ? err.message : 'Error');
      }
    } finally {
      copilotState.streaming = false;
      copilotState.streamAbortController = null;
      syncAllViews();
      refreshConversations();
      scrollMessagesToBottom();
    }
    return assistantMsg;
  }

  function stopStreaming() {
    if (copilotState.streamAbortController) {
      try {
        copilotState.streamAbortController.abort();
      } catch (_e) {
        /* ignore */
      }
    }
  }

  /* ── Shared View Builder (Works for BOTH Drawer & Full-Screen Workspace) ── */

  function buildApprovalCard(approval) {
    if (!approval) return null;
    var decided = approval.status && approval.status !== 'pending';
    var card = el('div', {
      class: 'hc-approval-card' + (decided ? ' is-decided' : ''),
      'data-approval-id': approval.approval_id
    });

    var hdr = el('div', { style: 'display:flex;justify-content:space-between;align-items:center;gap:8px;' }, [
      el('strong', null, tr('بوابة موافقة التنفيذ: ', 'Approval Gate: ') + (approval.action_type || 'ACTION')),
      el('span', { class: 'hc-badge ' + (approval.status === 'pending' ? 'hc-badge-warn' : 'hc-badge-info') }, approval.status || 'pending')
    ]);
    card.appendChild(hdr);

    var details = el('div', { class: 'ltr-isolate', dir: 'ltr', style: 'font-family:var(--font-mono);font-size:0.76rem;' }, [
      (approval.tool_name || 'engine') + ' -> ' + (approval.target || 'workspace') +
        (approval.command_args ? (' | ' + approval.command_args) : '')
    ]);
    card.appendChild(details);

    if (!decided) {
      var noteInput = el('input', {
        type: 'text',
        class: 'hc-input',
        placeholder: tr('ملاحظات القرار (اختياري)...', 'Decision note (optional)...')
      });
      var approveBtn = el('button', { type: 'button', class: 'hc-btn success' }, tr('موافقة وتنفيذ', 'Approve & Execute'));
      var rejectBtn = el('button', { type: 'button', class: 'hc-btn danger' }, tr('رفض', 'Reject'));

      async function submitDecision(decision) {
        approveBtn.disabled = true;
        rejectBtn.disabled = true;
        try {
          if (global.HunterPlatform) {
            var res = await global.HunterPlatform.decideApproval(approval.approval_id, decision, noteInput.value.trim());
            if (res && res.approval) {
              approval.status = res.approval.status;
            } else {
              approval.status = decision;
            }
          } else {
            var r = await apiJson('/api/platform/approvals/' + encodeURIComponent(approval.approval_id) + '/decide', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ decision: decision, note: noteInput.value.trim(), decided_by: 'operator' })
            });
            approval.status = (r.approval && r.approval.status) || decision;
          }
          toast(
            approval.status === 'approved'
              ? tr('تمت الموافقة وتنفيذ الإجراء.', 'Action approved.')
              : tr('تم رفض الإجراء.', 'Action rejected.'),
            approval.status === 'approved' ? 'success' : 'warning'
          );
          syncAllViews();
        } catch (err) {
          approveBtn.disabled = false;
          rejectBtn.disabled = false;
          toast(err.message, 'error');
        }
      }

      approveBtn.addEventListener('click', function () { submitDecision('approved'); });
      rejectBtn.addEventListener('click', function () { submitDecision('rejected'); });

      card.appendChild(noteInput);
      card.appendChild(el('div', { class: 'hc-approval-actions' }, [approveBtn, rejectBtn]));
    }
    return card;
  }

  function resolveApprovalForMessage(msg) {
    if (msg.approval) {
      if (global.HunterPlatform) {
        var plat = global.HunterPlatform.getState();
        var recent = (plat.approvals && plat.approvals.recent) || [];
        var match = recent.find(function (a) { return a.approval_id === msg.approval.approval_id; });
        if (match) return match;
      }
      return msg.approval;
    }
    if (msg.approval_id && global.HunterPlatform) {
      var st = global.HunterPlatform.getState();
      var list = (st.approvals && st.approvals.recent) || [];
      return list.find(function (a) { return a.approval_id === msg.approval_id; }) || null;
    }
    return null;
  }

  function renderSingleMessageNode(msg) {
    var roleCls = msg.role === 'user' ? 'user' : 'assistant';
    var node = el('article', {
      class: 'hc-msg ' + roleCls,
      'data-msg-id': msg.message_id || ''
    });

    var metaLeft = el('span', null, msg.role === 'user' ? tr('المشغّل', 'Operator') : 'HunterAI Copilot');
    var metaBadges = el('div', { style: 'display:flex;gap:6px;align-items:center;flex-wrap:wrap;' });
    if (msg.model && msg.role !== 'user') {
      metaBadges.appendChild(el('span', { class: 'hc-badge hc-badge-info ltr-isolate', dir: 'ltr' }, msg.model));
    }
    if (msg.metadata && msg.metadata.fallback) {
      metaBadges.appendChild(
        el('span', { class: 'hc-badge hc-badge-warn' }, tr('وضع بديل محلي (Offline)', 'Offline Fallback'))
      );
    }
    if (msg.pending) {
      metaBadges.appendChild(el('span', { class: 'hc-badge hc-badge-info' }, tr('بث حي...', 'Streaming...')));
    }

    node.appendChild(el('div', { class: 'hc-msg-head' }, [metaLeft, metaBadges]));

    var body = el('div', { class: 'hc-msg-body' });
    if (msg.role === 'user') {
      body.appendChild(el('p', { style: 'white-space:pre-wrap;margin:0;' }, msg.content || ''));
    } else if (msg.pending && !msg.content) {
      body.appendChild(el('p', { style: 'color:var(--text-muted);' }, tr('جارِ تحليل السياق المباشر...', 'Analyzing live platform context...')));
    } else {
      body.innerHTML = markdownToSafeHtml(msg.content || '');
      enhanceCodeBlocks(body);
    }
    node.appendChild(body);

    if (msg.policy_blocked && !msg.policy_blocked.allowed) {
      node.appendChild(
        el('div', { class: 'hc-badge hc-badge-danger', style: 'border-radius:6px;padding:6px 10px;' }, [
          tr('محظور بواسطة محرك السياسات: ', 'Blocked by Policy Engine: ') + (msg.policy_blocked.reason || msg.policy_blocked.status || '')
        ])
      );
    }

    var approvalObj = resolveApprovalForMessage(msg);
    if (approvalObj) {
      var aCard = buildApprovalCard(approvalObj);
      if (aCard) node.appendChild(aCard);
    }

    var refs = Array.isArray(msg.refs) ? msg.refs : [];
    if (refs.length > 0 && msg.role !== 'user') {
      var refsRow = el('div', { class: 'hc-refs', 'aria-label': tr('المراجع والانتقال السريع', 'Citations and quick navigation') });
      refs.slice(0, 8).forEach(function (ref) {
        var chip = el(
          'button',
          {
            type: 'button',
            class: 'hc-ref-chip',
            title: (ref.kind || '') + ': ' + (ref.id || ''),
            onclick: function () {
              if (global.HunterPlatform) {
                global.HunterPlatform.navigate(ref);
              }
            }
          },
          [(ref.kind ? '[' + ref.kind + '] ' : '') + (ref.label || ref.id || 'ref')]
        );
        refsRow.appendChild(chip);
      });
      node.appendChild(refsRow);
    }

    return node;
  }

  function updateMessageNode(msg) {
    if (!msg || !msg.message_id) return;
    _boundWorkspaces.forEach(function (ws) {
      if (!ws.messagesBox) return;
      var children = ws.messagesBox.children;
      for (var i = 0; i < children.length; i += 1) {
        if (children[i].getAttribute && children[i].getAttribute('data-msg-id') === msg.message_id) {
          ws.messagesBox.replaceChild(renderSingleMessageNode(msg), children[i]);
          break;
        }
      }
    });
  }

  function scrollMessagesToBottom() {
    _boundWorkspaces.forEach(function (ws) {
      if (ws.messagesBox) {
        ws.messagesBox.scrollTop = ws.messagesBox.scrollHeight;
      }
    });
  }

  function renderRunsStrip(stripEl) {
    if (!stripEl) return;
    stripEl.textContent = '';
    var pState = global.HunterPlatform ? global.HunterPlatform.getState() : null;
    var eng = global.HunterPlatform ? global.HunterPlatform.getActiveEngagement() : null;
    var runs = (pState && Array.isArray(pState.runs)) ? pState.runs : [];
    var activeRuns = runs.filter(function (r) {
      return r.status === 'running' || r.status === 'paused' || r.status === 'pending';
    });

    if (eng) {
      stripEl.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'hc-run-pill',
            onclick: function () {
              if (global.HunterPlatform) global.HunterPlatform.navigate({ section: 'targets', id: eng.engagement_id });
            }
          },
          tr('الهدف: ', 'Engagement: ') + (eng.name || eng.target || eng.engagement_id)
        )
      );
    }

    if (activeRuns.length === 0) {
      stripEl.appendChild(
        el('span', { class: 'hc-run-pill' }, tr('لا توجد تشغيلات نشطة (Standby)', 'No active runs (Standby)'))
      );
      return;
    }

    activeRuns.slice(0, 4).forEach(function (r) {
      var pct = typeof r.progress === 'number' ? (' ' + Math.round(r.progress) + '%') : '';
      stripEl.appendChild(
        el(
          'button',
          {
            type: 'button',
            class: 'hc-run-pill is-active',
            title: tr('انتقل إلى تفاصيل التشغيل دون مقاطعته', 'Inspect run without interrupting'),
            onclick: function () {
              if (global.HunterPlatform) global.HunterPlatform.navigate({ kind: 'run', id: r.run_id, section: 'overview' });
            }
          },
          '● ' + (r.kind || 'run') + ' · ' + (r.current_phase || r.status) + pct
        )
      );
    });
  }

  function renderWorkspace(ws) {
    if (!ws) return;
    renderRunsStrip(ws.runsStrip);

    // Conversations dropdown
    if (ws.convSelect) {
      ws.convSelect.textContent = '';
      if (copilotState.conversations.length === 0) {
        ws.convSelect.appendChild(el('option', { value: '' }, tr('جلسة جديدة...', 'New session...')));
      } else {
        copilotState.conversations.forEach(function (c) {
          var opt = el('option', { value: c.conversation_id }, (c.title || c.conversation_id));
          if (c.conversation_id === copilotState.activeConversationId) opt.selected = true;
          ws.convSelect.appendChild(opt);
        });
      }
    }

    // Inline rename/delete bar
    if (ws.actionSlot) {
      ws.actionSlot.textContent = '';
      if (copilotState.renaming && copilotState.activeConversationId) {
        var curConv = copilotState.conversations.find(function (c) { return c.conversation_id === copilotState.activeConversationId; });
        var renameInp = el('input', {
          type: 'text',
          class: 'hc-input',
          style: 'flex:1;',
          value: (curConv && curConv.title) || '',
          'aria-label': tr('اسم المحادثة الجديد', 'New conversation title')
        });
        var saveRenameBtn = el(
          'button',
          {
            type: 'button',
            class: 'hc-btn primary',
            onclick: function () { renameConversation(copilotState.activeConversationId, renameInp.value); }
          },
          tr('حفظ', 'Save')
        );
        var cancelRenameBtn = el(
          'button',
          {
            type: 'button',
            class: 'hc-btn',
            onclick: function () { copilotState.renaming = false; syncAllViews(); }
          },
          tr('إلغاء', 'Cancel')
        );
        ws.actionSlot.appendChild(el('div', { class: 'hc-inline-confirm' }, [renameInp, saveRenameBtn, cancelRenameBtn]));
      } else if (copilotState.confirmDeleteId) {
        var delId = copilotState.confirmDeleteId;
        var yesDel = el(
          'button',
          {
            type: 'button',
            class: 'hc-btn danger',
            onclick: function () { deleteConversation(delId); }
          },
          tr('تأكيد الحذف', 'Confirm Delete')
        );
        var noDel = el(
          'button',
          {
            type: 'button',
            class: 'hc-btn',
            onclick: function () { copilotState.confirmDeleteId = null; syncAllViews(); }
          },
          tr('إلغاء', 'Cancel')
        );
        ws.actionSlot.appendChild(
          el('div', { class: 'hc-inline-confirm' }, [
            el('span', { style: 'flex:1;' }, tr('هل تريد حذف هذه الجلسة؟', 'Delete this conversation?')),
            yesDel,
            noDel
          ])
        );
      }
    }

    // Model & Mode selectors
    if (ws.modelSelect) {
      ws.modelSelect.textContent = '';
      var models = copilotState.models.length ? copilotState.models : [{ id: 'auto', label: 'Auto (Smart Router)' }];
      models.forEach(function (m) {
        var opt = el('option', { value: m.id }, m.label);
        if (m.id === copilotState.selectedModel) opt.selected = true;
        ws.modelSelect.appendChild(opt);
      });
    }
    if (ws.modeSelect) {
      ws.modeSelect.textContent = '';
      MODES.forEach(function (md) {
        var opt = el('option', { value: md.value }, lang() === 'en' ? md.en : md.ar);
        if (md.value === copilotState.selectedMode) opt.selected = true;
        ws.modeSelect.appendChild(opt);
      });
    }

    // Messages
    if (ws.messagesBox) {
      ws.messagesBox.textContent = '';
      if (copilotState.messages.length === 0) {
        var prompts = [
          tr('ما هي حالة الهدف الحالي والتشغيلات النشطة؟', 'Summarize active engagement, runs, and pending approvals'),
          tr('اعرض أهم الثغرات والأدلة الموثقة حتى الآن', 'List verified findings and evidence citations'),
          tr('اقترح خطة فحص IDOR و SSRF ضمن النطاق', 'Plan authorized IDOR & SSRF tests within scope')
        ];
        var emptyBox = el('div', { class: 'hc-empty' }, [
          el('div', { class: 'hc-empty-title' }, tr('مساعد HunterAI الذكي المستمر', 'HunterAI Grounded Copilot')),
          el('div', { style: 'font-size:0.82rem;line-height:1.5;' }, tr(
            'يستعلم مباشرة عن الأهداف والتشغيلات الجارية دون مقاطعتها، مع عزل البيانات غير الموثوقة وتطبيق حراسة النطاق.',
            'Queries live runs, assets, findings, and approvals concurrently without interrupting active jobs.'
          )),
          el(
            'div',
            { style: 'display:flex;flex-direction:column;gap:6px;margin-top:6px;' },
            prompts.map(function (p) {
              return el(
                'button',
                {
                  type: 'button',
                  class: 'hc-ref-chip',
                  style: 'justify-content:center;padding:8px 12px;border-radius:8px;',
                  onclick: function () {
                    ws.textarea.value = p;
                    ws.textarea.focus();
                  }
                },
                p
              );
            })
          )
        ]);
        ws.messagesBox.appendChild(emptyBox);
      } else {
        copilotState.messages.forEach(function (m) {
          ws.messagesBox.appendChild(renderSingleMessageNode(m));
        });
      }
    }

    // Attachments
    if (ws.attachBox) {
      ws.attachBox.textContent = '';
      copilotState.attachments.forEach(function (att) {
        var rm = el(
          'button',
          {
            type: 'button',
            style: 'background:none;border:none;color:var(--text-muted);cursor:pointer;padding:0 2px;',
            'aria-label': tr('إزالة المرفق', 'Remove attachment'),
            onclick: function () {
              copilotState.attachments = copilotState.attachments.filter(function (a) {
                return a.attachment_id !== att.attachment_id;
              });
              syncAllViews();
            }
          },
          '✕'
        );
        ws.attachBox.appendChild(el('span', { class: 'hc-attach-chip ltr-isolate', dir: 'ltr' }, [att.filename, rm]));
      });
    }

    if (ws.sendBtn && ws.stopBtn) {
      ws.sendBtn.style.display = copilotState.streaming ? 'none' : 'inline-flex';
      ws.stopBtn.style.display = copilotState.streaming ? 'inline-flex' : 'none';
    }
  }

  function syncAllViews() {
    _boundWorkspaces.forEach(renderWorkspace);
    if (_drawerEls && _drawerEls.drawer) {
      _drawerEls.drawer.classList.toggle('is-open', copilotState.open);
      _drawerEls.drawer.classList.toggle('is-expanded', copilotState.expanded);
      _drawerEls.drawer.style.setProperty('--hc-width', copilotState.width + 'px');
      if (_drawerEls.resizer) {
        _drawerEls.resizer.setAttribute('aria-valuenow', String(copilotState.width));
      }
    }
  }

  function createWorkspaceUI(options) {
    var opts = options || {};
    var convSelect = el('select', {
      class: 'hc-select',
      'aria-label': tr('جلسة المحادثة', 'Copilot conversation')
    });
    convSelect.addEventListener('change', function () {
      if (convSelect.value) selectConversation(convSelect.value);
    });

    var newBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-icon-btn',
        title: tr('محادثة جديدة', 'New conversation'),
        'aria-label': tr('محادثة جديدة', 'New conversation'),
        onclick: function () { createConversation(); }
      },
      '＋'
    );
    var renameBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-icon-btn',
        title: tr('إعادة تسمية', 'Rename conversation'),
        'aria-label': tr('إعادة تسمية', 'Rename conversation'),
        onclick: function () {
          if (!copilotState.activeConversationId) return;
          copilotState.renaming = !copilotState.renaming;
          copilotState.confirmDeleteId = null;
          syncAllViews();
        }
      },
      '✎'
    );
    var delBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-icon-btn',
        title: tr('حذف المحادثة', 'Delete conversation'),
        'aria-label': tr('حذف المحادثة', 'Delete conversation'),
        onclick: function () {
          if (!copilotState.activeConversationId) return;
          copilotState.confirmDeleteId = copilotState.confirmDeleteId ? null : copilotState.activeConversationId;
          copilotState.renaming = false;
          syncAllViews();
        }
      },
      '🗑'
    );

    var modelSelect = el('select', { class: 'hc-select ltr-isolate', dir: 'ltr', 'aria-label': tr('نموذج الذكاء الاصطناعي', 'Model') });
    modelSelect.addEventListener('change', function () {
      copilotState.selectedModel = modelSelect.value;
      if (copilotState.activeConversationId) {
        apiJson('/api/copilot/conversations/' + encodeURIComponent(copilotState.activeConversationId), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: copilotState.selectedModel })
        }).catch(function () {});
      }
    });

    var modeSelect = el('select', { class: 'hc-select', 'aria-label': tr('نمط العمل', 'Copilot mode') });
    modeSelect.addEventListener('change', function () {
      copilotState.selectedMode = modeSelect.value;
      if (copilotState.activeConversationId) {
        apiJson('/api/copilot/conversations/' + encodeURIComponent(copilotState.activeConversationId), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: copilotState.selectedMode })
        }).catch(function () {});
      }
    });

    var actionSlot = el('div');
    var runsStrip = el('div', { class: 'hc-runs-strip', 'aria-label': tr('التشغيلات النشطة', 'Live active runs') });
    var messagesBox = el('div', { class: 'hc-messages', role: 'log', 'aria-live': 'polite' });
    var attachBox = el('div', { class: 'hc-attach-list' });
    var fileInput = el('input', { type: 'file', style: 'display:none;', multiple: true });
    fileInput.addEventListener('change', function () {
      var files = Array.prototype.slice.call(fileInput.files || []);
      files.forEach(function (f) { uploadAttachment(f).catch(function (e) { toast(e.message, 'error'); }); });
      fileInput.value = '';
    });

    var attachBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-icon-btn',
        title: tr('إرفاق ملف للتحليل', 'Attach file'),
        'aria-label': tr('إرفاق ملف', 'Attach file'),
        onclick: function () { fileInput.click(); }
      },
      '📎'
    );
    var textarea = el('textarea', {
      class: 'hc-textarea',
      rows: 1,
      placeholder: tr('اسأل المساعد عن الهدف، السجلات، أو اطلب تحليلاً... (Enter للإرسال)', 'Ask Copilot about active engagement, findings, logs, or request an action...')
    });
    var sendBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-btn primary',
        style: 'min-height:44px;',
        onclick: function () {
          var v = textarea.value;
          if (!v.trim()) return;
          textarea.value = '';
          sendMessage(v);
        }
      },
      tr('إرسال', 'Send')
    );
    var stopBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-btn danger',
        style: 'min-height:44px;display:none;',
        onclick: stopStreaming
      },
      tr('إيقاف', 'Stop')
    );

    textarea.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !ev.shiftKey) {
        ev.preventDefault();
        var v = textarea.value;
        if (!v.trim()) return;
        textarea.value = '';
        sendMessage(v);
      }
    });

    var controls = el('div', { class: 'hc-controls' }, [
      el('div', { class: 'hc-ctrl-row' }, [convSelect, newBtn, renameBtn, delBtn]),
      actionSlot,
      el('div', { class: 'hc-ctrl-row' }, [modelSelect, modeSelect])
    ]);

    var composer = el('div', { class: 'hc-composer' }, [
      attachBox,
      fileInput,
      el('div', { class: 'hc-composer-row' }, [attachBtn, textarea, sendBtn, stopBtn])
    ]);

    var ws = {
      id: opts.id || 'ws',
      runsStrip: runsStrip,
      controls: controls,
      convSelect: convSelect,
      actionSlot: actionSlot,
      modelSelect: modelSelect,
      modeSelect: modeSelect,
      messagesBox: messagesBox,
      attachBox: attachBox,
      textarea: textarea,
      sendBtn: sendBtn,
      stopBtn: stopBtn
    };
    _boundWorkspaces.push(ws);
    return ws;
  }

  /* ── Drawer Mounting & Resizing ────────────────────────────────────────── */

  function mountDrawer() {
    if (_drawerEls || typeof document === 'undefined' || !document.body) return _drawerEls;
    ensureStyles();

    var savedW = parseInt(safeReadStorage(WIDTH_KEY, '440'), 10);
    if (!isNaN(savedW) && savedW >= MIN_WIDTH && savedW <= MAX_WIDTH) {
      copilotState.width = savedW;
    }
    copilotState.open = safeReadStorage(OPEN_KEY, 'false') === 'true';

    var ws = createWorkspaceUI({ id: 'drawer' });

    var resizer = el('div', {
      class: 'hc-resizer',
      role: 'separator',
      'aria-orientation': 'vertical',
      'aria-label': tr('تغيير عرض لوحة المساعد', 'Resize Copilot drawer'),
      'aria-valuemin': String(MIN_WIDTH),
      'aria-valuemax': String(MAX_WIDTH),
      'aria-valuenow': String(copilotState.width),
      tabindex: '0'
    });

    var expandBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-icon-btn',
        title: tr('توسيع لملء الشاشة', 'Toggle full-screen / chat workspace'),
        'aria-label': tr('توسيع لملء الشاشة', 'Toggle full-screen'),
        onclick: function () {
          var hasSecChat = Boolean(document.getElementById('sec-chat')) && typeof global.switchSection === 'function';
          if (hasSecChat && !copilotState.expanded) {
            close();
            global.switchSection('chat');
            return;
          }
          copilotState.expanded = !copilotState.expanded;
          syncAllViews();
        }
      },
      '⛶'
    );

    var closeBtn = el(
      'button',
      {
        type: 'button',
        class: 'hc-icon-btn',
        title: tr('إغلاق (Ctrl+J)', 'Close Copilot (Ctrl+J)'),
        'aria-label': tr('إغلاق لوحة المساعد', 'Close Copilot drawer'),
        onclick: close
      },
      '✕'
    );

    var header = el('div', { class: 'hc-header' }, [
      el('div', { class: 'hc-title-wrap' }, [
        el('span', { class: 'hc-badge hc-badge-info' }, 'AI'),
        el('h2', { id: 'hunterCopilotTitle', class: 'hc-title' }, 'HunterAI Copilot')
      ]),
      el('div', { class: 'hc-header-actions' }, [expandBtn, closeBtn])
    ]);

    var drawer = el(
      'aside',
      {
        id: 'hunterCopilotDrawer',
        class: 'hc-drawer',
        role: 'complementary',
        'aria-labelledby': 'hunterCopilotTitle'
      },
      [resizer, header, ws.runsStrip, ws.controls, ws.messagesBox, ws.composer]
    );

    // Drag resize (direction-aware for RTL/LTR)
    var dragging = false;
    var startX = 0;
    var startW = copilotState.width;

    resizer.addEventListener('mousedown', function (ev) {
      ev.preventDefault();
      dragging = true;
      startX = ev.clientX;
      startW = copilotState.width;
      document.body.style.cursor = 'col-resize';
    });

    document.addEventListener('mousemove', function (ev) {
      if (!dragging) return;
      var isRtl = document.documentElement.getAttribute('dir') === 'rtl';
      var delta = isRtl ? (ev.clientX - startX) : (startX - ev.clientX);
      var nextW = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, startW + delta));
      copilotState.width = nextW;
      drawer.style.setProperty('--hc-width', nextW + 'px');
      resizer.setAttribute('aria-valuenow', String(nextW));
    });

    document.addEventListener('mouseup', function () {
      if (!dragging) return;
      dragging = false;
      document.body.style.cursor = '';
      safeWriteStorage(WIDTH_KEY, copilotState.width);
    });

    // Keyboard resize
    resizer.addEventListener('keydown', function (ev) {
      var isRtl = document.documentElement.getAttribute('dir') === 'rtl';
      var step = ev.shiftKey ? 40 : 16;
      var next = null;
      if (ev.key === 'ArrowLeft') {
        next = copilotState.width + (isRtl ? -step : step);
      } else if (ev.key === 'ArrowRight') {
        next = copilotState.width + (isRtl ? step : -step);
      } else if (ev.key === 'Home') {
        next = MAX_WIDTH;
      } else if (ev.key === 'End') {
        next = MIN_WIDTH;
      }
      if (next !== null) {
        ev.preventDefault();
        copilotState.width = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, next));
        safeWriteStorage(WIDTH_KEY, copilotState.width);
        syncAllViews();
      }
    });

    var mountTarget = document.getElementById('hunterCopilotMount') || document.body;
    mountTarget.appendChild(drawer);
    _drawerEls = { drawer: drawer, resizer: resizer, workspace: ws };
    syncAllViews();
    return _drawerEls;
  }

  function mountWorkspaceInto(targetEl) {
    if (!targetEl) return null;
    ensureStyles();
    targetEl.textContent = '';
    var ws = createWorkspaceUI({ id: 'embedded' });
    var shell = el('div', { class: 'hc-workspace-shell' }, [
      ws.runsStrip,
      ws.controls,
      ws.messagesBox,
      ws.composer
    ]);
    targetEl.appendChild(shell);
    renderWorkspace(ws);
    return ws;
  }

  function open() {
    mountDrawer();
    copilotState.open = true;
    safeWriteStorage(OPEN_KEY, 'true');
    syncAllViews();
    if (_drawerEls && _drawerEls.workspace && _drawerEls.workspace.textarea) {
      setTimeout(function () { _drawerEls.workspace.textarea.focus(); }, 20);
    }
  }

  function close() {
    copilotState.open = false;
    copilotState.expanded = false;
    safeWriteStorage(OPEN_KEY, 'false');
    syncAllViews();
  }

  function toggle() {
    if (copilotState.open) close();
    else open();
  }

  function setDraftPrompt(text) {
    _boundWorkspaces.forEach(function (ws) {
      if (ws.textarea) ws.textarea.value = String(text || '');
    });
  }

  function bindGlobalEvents() {
    if (typeof document === 'undefined' || bindGlobalEvents._bound) return;
    bindGlobalEvents._bound = true;

    document.addEventListener('keydown', function (ev) {
      if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && ev.key.toLowerCase() === 'j') {
        ev.preventDefault();
        toggle();
      }
    });

    document.addEventListener('click', function (ev) {
      var btn = ev.target && ev.target.closest ? ev.target.closest('[data-hunter-copilot-toggle]') : null;
      if (btn) {
        ev.preventDefault();
        toggle();
      }
    });

    if (typeof window !== 'undefined') {
      window.addEventListener('hunter:state', function (ev) {
        var detail = ev.detail || {};
        var ctxConv = detail.context && detail.context.active_conversation_id;
        if (ctxConv && !copilotState.activeConversationId && !copilotState.streaming) {
          selectConversation(ctxConv);
        }
        _boundWorkspaces.forEach(function (ws) {
          renderRunsStrip(ws.runsStrip);
        });
      });
      window.addEventListener('hunter:langchange', syncAllViews);
      window.addEventListener('hunter:themechange', syncAllViews);
    }
  }

  function init() {
    bindGlobalEvents();
    mountDrawer();
    loadModelsCatalog();
    refreshConversations();
  }

  var HunterCopilot = {
    version: '1.0.0',
    init: init,
    open: open,
    close: close,
    toggle: toggle,
    mountWorkspaceInto: mountWorkspaceInto,
    createConversation: createConversation,
    selectConversation: selectConversation,
    refreshConversations: refreshConversations,
    sendMessage: sendMessage,
    stopStreaming: stopStreaming,
    setDraftPrompt: setDraftPrompt,
    getState: function () {
      return Object.assign({}, copilotState);
    }
  };

  global.HunterCopilot = HunterCopilot;

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = HunterCopilot;
  }
})(typeof window !== 'undefined' ? window : globalThis);
