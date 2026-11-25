/* ==========================================================================
   HunterAI UI Core Utilities (window.HunterCore)
   Zero-dependency runtime helpers for XSS-safe DOM, theme, i18n, toasts,
   and visibility-aware AbortController polling.
   ========================================================================== */
(function (global) {
  'use strict';

  var THEME_STORAGE_KEY = 'hunterai_theme';
  var LANG_STORAGE_KEY = 'hunterai_lang';
  var DEFAULT_CATALOG_URL = '/static/i18n/catalog.json';

  var VALID_THEMES = { dark: true, light: true };
  var VALID_LANGS = { ar: true, en: true };

  var SAFE_FALLBACK_TAGS = {
    A: true,
    B: true,
    BLOCKQUOTE: true,
    BR: true,
    CODE: true,
    DIV: true,
    EM: true,
    H1: true,
    H2: true,
    H3: true,
    H4: true,
    H5: true,
    H6: true,
    HR: true,
    I: true,
    KBD: true,
    LI: true,
    OL: true,
    P: true,
    PRE: true,
    S: true,
    SAMP: true,
    SPAN: true,
    STRONG: true,
    TABLE: true,
    TBODY: true,
    TD: true,
    TH: true,
    THEAD: true,
    TR: true,
    U: true,
    UL: true
  };

  var DROP_WITH_CONTENT_TAGS = {
    BASE: true,
    EMBED: true,
    FRAME: true,
    FRAMESET: true,
    IFRAME: true,
    LINK: true,
    MATH: true,
    META: true,
    NOSCRIPT: true,
    OBJECT: true,
    SCRIPT: true,
    STYLE: true,
    SVG: true,
    TEMPLATE: true,
    TEXTAREA: true,
    TITLE: true
  };

  var SAFE_FALLBACK_ATTRS = {
    class: true,
    dir: true,
    href: true,
    lang: true,
    rel: true,
    title: true
  };

  var BOOLEAN_ATTRS = {
    checked: true,
    disabled: true,
    hidden: true,
    multiple: true,
    open: true,
    readonly: true,
    readOnly: true,
    required: true,
    selected: true
  };

  var state = {
    theme: 'dark',
    lang: 'ar',
    catalog: null,
    catalogUrl: DEFAULT_CATALOG_URL,
    catalogPromise: null,
    toastContainer: null
  };

  function hasWindow() {
    return typeof window !== 'undefined';
  }

  function hasDocument() {
    return typeof document !== 'undefined';
  }

  function safeStorageGet(key) {
    try {
      if (hasWindow() && window.localStorage) {
        return window.localStorage.getItem(key);
      }
    } catch (_err) {
      /* Storage may be unavailable in restricted contexts */
    }
    return null;
  }

  function safeStorageSet(key, value) {
    try {
      if (hasWindow() && window.localStorage) {
        window.localStorage.setItem(key, value);
      }
    } catch (_err) {
      /* Ignore storage quota or privacy-mode failures */
    }
  }

  function readQueryParam(name) {
    if (!hasWindow() || !window.location || !window.location.search) {
      return null;
    }
    try {
      var params = new URLSearchParams(window.location.search);
      return params.get(name);
    } catch (_err) {
      return null;
    }
  }

  /* ── 1. Escaping & Sanitization ────────────────────────────────────────── */

  function escapeHtml(value) {
    if (value === null || value === undefined) {
      return '';
    }
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, '&#96;');
  }

  function safeHref(url, fallback) {
    var defaultHref = typeof fallback === 'string' ? fallback : '#';
    if (typeof url !== 'string') {
      return defaultHref;
    }
    var trimmed = url.trim();
    if (!trimmed) {
      return defaultHref;
    }
    /* Reject ASCII control characters that browsers may strip inside schemes */
    if (/[\u0000-\u001F\u007F]/.test(trimmed)) {
      return defaultHref;
    }
    /* Allow single-leading-slash relative paths, rejecting // or /\ protocol-relative URLs */
    if (trimmed.charAt(0) === '/') {
      if (trimmed.length > 1 && (trimmed.charAt(1) === '/' || trimmed.charAt(1) === '\\')) {
        return defaultHref;
      }
      return trimmed;
    }
    try {
      var parsed = new URL(trimmed);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.href;
      }
    } catch (_err) {
      return defaultHref;
    }
    return defaultHref;
  }

  function sanitizeNodeFallback(parent) {
    var children = Array.prototype.slice.call(parent.childNodes);
    for (var i = 0; i < children.length; i += 1) {
      var node = children[i];
      if (node.nodeType === 3) {
        continue;
      }
      if (node.nodeType !== 1) {
        parent.removeChild(node);
        continue;
      }
      var tag = node.tagName ? node.tagName.toUpperCase() : '';
      if (DROP_WITH_CONTENT_TAGS[tag]) {
        parent.removeChild(node);
        continue;
      }
      sanitizeNodeFallback(node);
      if (!SAFE_FALLBACK_TAGS[tag]) {
        while (node.firstChild) {
          parent.insertBefore(node.firstChild, node);
        }
        parent.removeChild(node);
        continue;
      }
      var attrs = Array.prototype.slice.call(node.attributes);
      for (var j = 0; j < attrs.length; j += 1) {
        var attrName = attrs[j].name.toLowerCase();
        if (!SAFE_FALLBACK_ATTRS[attrName]) {
          node.removeAttribute(attrs[j].name);
          continue;
        }
        if (attrName === 'href') {
          var safe = safeHref(attrs[j].value, '#');
          node.setAttribute('href', safe);
          if (/^https?:\/\//i.test(safe)) {
            node.setAttribute('rel', 'noopener noreferrer');
          }
        }
      }
    }
  }

  function sanitizeHtml(html, options) {
    var raw = html === null || html === undefined ? '' : String(html);
    if (!raw) {
      return '';
    }
    var purifier = global.DOMPurify || (hasWindow() && window.DOMPurify);
    if (purifier && typeof purifier.sanitize === 'function') {
      var cfg = Object.assign(
        {
          FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form'],
          FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur'],
          ALLOW_DATA_ATTR: false
        },
        options || {}
      );
      return purifier.sanitize(raw, cfg);
    }
    if (hasDocument()) {
      var tpl = document.createElement('template');
      tpl.innerHTML = raw;
      sanitizeNodeFallback(tpl.content);
      var container = document.createElement('div');
      container.appendChild(tpl.content);
      return container.innerHTML;
    }
    return escapeHtml(raw);
  }

  /* ── 2. Safe DOM Element Builder ───────────────────────────────────────── */

  function appendChildSafe(parent, child) {
    if (child === null || child === undefined || child === false || child === true) {
      return;
    }
    if (Array.isArray(child)) {
      for (var i = 0; i < child.length; i += 1) {
        appendChildSafe(parent, child[i]);
      }
      return;
    }
    if (typeof Node !== 'undefined' && child instanceof Node) {
      parent.appendChild(child);
      return;
    }
    parent.appendChild(document.createTextNode(String(child)));
  }

  function el(tag, attrs, children) {
    if (!hasDocument()) {
      throw new Error('HunterCore.el requires a browser DOM document');
    }
    var node = document.createElement(tag);
    if (attrs && typeof attrs === 'object') {
      var keys = Object.keys(attrs);
      for (var i = 0; i < keys.length; i += 1) {
        var key = keys[i];
        var val = attrs[key];
        if (val === null || val === undefined) {
          continue;
        }
        if (key === 'class' || key === 'className') {
          node.className = String(val);
        } else if (key === 'text' || key === 'textContent') {
          node.textContent = String(val);
        } else if (key === 'style') {
          if (typeof val === 'string') {
            node.setAttribute('style', val);
          } else if (typeof val === 'object') {
            Object.assign(node.style, val);
          }
        } else if (key === 'dataset' && typeof val === 'object') {
          var dKeys = Object.keys(val);
          for (var d = 0; d < dKeys.length; d += 1) {
            if (val[dKeys[d]] !== null && val[dKeys[d]] !== undefined) {
              node.dataset[dKeys[d]] = String(val[dKeys[d]]);
            }
          }
        } else if (key.indexOf('on') === 0 && typeof val === 'function') {
          node.addEventListener(key.slice(2).toLowerCase(), val);
        } else if (key === 'href') {
          node.setAttribute('href', safeHref(String(val), '#'));
        } else if (key === 'innerHTML' || key === 'outerHTML') {
          /* Disallow raw HTML sinks via el() attrs */
          continue;
        } else if (BOOLEAN_ATTRS[key]) {
          var attrKey = key === 'readOnly' ? 'readonly' : key;
          if (val) {
            node.setAttribute(attrKey, '');
            if (key in node) {
              node[key] = true;
            }
          } else {
            node.removeAttribute(attrKey);
            if (key in node) {
              node[key] = false;
            }
          }
        } else if (key === 'value' && 'value' in node) {
          node.value = String(val);
          node.setAttribute('value', String(val));
        } else {
          node.setAttribute(key, String(val));
        }
      }
    }
    if (children !== undefined) {
      appendChildSafe(node, children);
    }
    return node;
  }

  /* ── 3. Theme Sync ─────────────────────────────────────────────────────── */

  function normalizeTheme(theme) {
    if (typeof theme === 'string') {
      var low = theme.trim().toLowerCase();
      if (VALID_THEMES[low]) {
        return low;
      }
    }
    return 'dark';
  }

  function resolveInitialTheme() {
    var queryTheme = readQueryParam('theme');
    if (queryTheme && VALID_THEMES[queryTheme.trim().toLowerCase()]) {
      var q = queryTheme.trim().toLowerCase();
      safeStorageSet(THEME_STORAGE_KEY, q);
      return q;
    }
    var stored = safeStorageGet(THEME_STORAGE_KEY);
    if (stored && VALID_THEMES[stored.trim().toLowerCase()]) {
      return stored.trim().toLowerCase();
    }
    if (hasDocument() && document.documentElement) {
      var attr = document.documentElement.getAttribute('data-theme');
      if (attr && VALID_THEMES[attr.trim().toLowerCase()]) {
        return attr.trim().toLowerCase();
      }
    }
    return 'dark';
  }

  function setTheme(theme, options) {
    var opts = options || {};
    var next = normalizeTheme(theme);
    state.theme = next;
    if (hasDocument() && document.documentElement) {
      document.documentElement.setAttribute('data-theme', next);
    }
    if (opts.persist !== false) {
      safeStorageSet(THEME_STORAGE_KEY, next);
    }
    if (hasWindow() && typeof CustomEvent === 'function') {
      window.dispatchEvent(new CustomEvent('hunter:themechange', { detail: { theme: next } }));
    }
    return next;
  }

  function getTheme() {
    if (hasDocument() && document.documentElement) {
      var attr = document.documentElement.getAttribute('data-theme');
      if (attr && VALID_THEMES[attr]) {
        return attr;
      }
    }
    return state.theme;
  }

  function toggleTheme() {
    return setTheme(getTheme() === 'dark' ? 'light' : 'dark');
  }

  function initTheme() {
    return setTheme(resolveInitialTheme());
  }

  /* ── 4. i18n Loader & Translator ───────────────────────────────────────── */

  function normalizeLang(lang) {
    if (typeof lang === 'string') {
      var low = lang.trim().toLowerCase();
      if (VALID_LANGS[low]) {
        return low;
      }
    }
    return 'ar';
  }

  function resolveInitialLang() {
    var queryLang = readQueryParam('lang');
    if (queryLang && VALID_LANGS[queryLang.trim().toLowerCase()]) {
      var q = queryLang.trim().toLowerCase();
      safeStorageSet(LANG_STORAGE_KEY, q);
      return q;
    }
    var stored = safeStorageGet(LANG_STORAGE_KEY);
    if (stored && VALID_LANGS[stored.trim().toLowerCase()]) {
      return stored.trim().toLowerCase();
    }
    if (hasDocument() && document.documentElement) {
      var docLang = document.documentElement.getAttribute('lang');
      if (docLang && VALID_LANGS[docLang.trim().toLowerCase()]) {
        return docLang.trim().toLowerCase();
      }
    }
    return 'ar';
  }

  function applyLanguageAttributes(lang) {
    var normalized = normalizeLang(lang);
    var dir = normalized === 'ar' ? 'rtl' : 'ltr';
    if (hasDocument() && document.documentElement) {
      document.documentElement.setAttribute('lang', normalized);
      document.documentElement.setAttribute('dir', dir);
    }
    return { lang: normalized, dir: dir };
  }

  function lookupPath(obj, path) {
    if (!obj || typeof obj !== 'object' || typeof path !== 'string') {
      return undefined;
    }
    var parts = path.split('.');
    var cur = obj;
    for (var i = 0; i < parts.length; i += 1) {
      if (cur === null || cur === undefined || typeof cur !== 'object') {
        return undefined;
      }
      cur = cur[parts[i]];
    }
    return typeof cur === 'string' ? cur : undefined;
  }

  function formatTemplate(template, vars) {
    if (!vars || typeof vars !== 'object') {
      return template;
    }
    return template.replace(/\{([a-zA-Z0-9_]+)\}/g, function (match, key) {
      return Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : match;
    });
  }

  function t(key, fallbackOrVars, maybeVars) {
    var fallback = typeof fallbackOrVars === 'string' ? fallbackOrVars : key;
    var vars =
      fallbackOrVars && typeof fallbackOrVars === 'object' ? fallbackOrVars : maybeVars;
    var lang = state.lang;
    var resolved;
    if (state.catalog) {
      resolved =
        lookupPath(state.catalog[lang], key) ||
        lookupPath(state.catalog.en, key) ||
        lookupPath(state.catalog.ar, key);
    }
    return formatTemplate(resolved !== undefined ? resolved : fallback, vars);
  }

  function loadCatalog(url) {
    var targetUrl = url || state.catalogUrl || DEFAULT_CATALOG_URL;
    if (state.catalog && state.catalogUrl === targetUrl) {
      return Promise.resolve(state.catalog);
    }
    if (state.catalogPromise && state.catalogUrl === targetUrl) {
      return state.catalogPromise;
    }
    state.catalogUrl = targetUrl;
    if (typeof fetch !== 'function') {
      return Promise.resolve(state.catalog || { ar: {}, en: {} });
    }
    state.catalogPromise = fetch(targetUrl, { headers: { Accept: 'application/json' } })
      .then(function (res) {
        if (!res.ok) {
          throw new Error('Failed to load i18n catalog: HTTP ' + res.status);
        }
        return res.json();
      })
      .then(function (data) {
        state.catalog = data || { ar: {}, en: {} };
        return state.catalog;
      })
      .catch(function (err) {
        state.catalogPromise = null;
        if (typeof console !== 'undefined' && console.warn) {
          console.warn('[HunterCore] i18n catalog fetch error:', err);
        }
        return state.catalog || { ar: {}, en: {} };
      });
    return state.catalogPromise;
  }

  function applySingleElementTranslation(node) {
    if (!node || !node.getAttribute) {
      return;
    }
    var key = node.getAttribute('data-i18n');
    if (key) {
      var currentText = node.textContent;
      node.textContent = t(key, currentText || key);
    }
    var phKey = node.getAttribute('data-i18n-placeholder');
    if (phKey) {
      node.setAttribute('placeholder', t(phKey, node.getAttribute('placeholder') || phKey));
    }
    var titleKey = node.getAttribute('data-i18n-title');
    if (titleKey) {
      node.setAttribute('title', t(titleKey, node.getAttribute('title') || titleKey));
    }
    var ariaKey = node.getAttribute('data-i18n-aria-label');
    if (ariaKey) {
      node.setAttribute('aria-label', t(ariaKey, node.getAttribute('aria-label') || ariaKey));
    }
    var valKey = node.getAttribute('data-i18n-value');
    if (valKey) {
      var val = t(valKey, node.value || valKey);
      node.value = val;
      node.setAttribute('value', val);
    }
  }

  function applyTranslations(root) {
    if (!hasDocument()) {
      return 0;
    }
    var scope = root || document;
    if (!scope || typeof scope.querySelectorAll !== 'function') {
      return 0;
    }
    var selector =
      '[data-i18n],[data-i18n-placeholder],[data-i18n-title],[data-i18n-aria-label],[data-i18n-value]';
    var count = 0;
    if (scope.nodeType === 1 && scope.matches && scope.matches(selector)) {
      applySingleElementTranslation(scope);
      count += 1;
    }
    var nodes = scope.querySelectorAll(selector);
    for (var i = 0; i < nodes.length; i += 1) {
      applySingleElementTranslation(nodes[i]);
      count += 1;
    }
    return count;
  }

  function setLang(lang, options) {
    var opts = options || {};
    var next = normalizeLang(lang);
    state.lang = next;
    var meta = applyLanguageAttributes(next);
    if (opts.persist !== false) {
      safeStorageSet(LANG_STORAGE_KEY, next);
    }
    var ready = state.catalog ? Promise.resolve(state.catalog) : loadCatalog(opts.catalogUrl);
    return ready.then(function () {
      if (opts.apply !== false) {
        applyTranslations(opts.root || (hasDocument() ? document : null));
      }
      if (hasWindow() && typeof CustomEvent === 'function') {
        window.dispatchEvent(new CustomEvent('hunter:langchange', { detail: meta }));
      }
      return meta;
    });
  }

  function getLang() {
    return state.lang;
  }

  function getCatalog() {
    return state.catalog;
  }

  function initI18n(options) {
    var opts = options || {};
    var initial = resolveInitialLang();
    return setLang(initial, {
      persist: true,
      catalogUrl: opts.catalogUrl,
      root: opts.root,
      apply: opts.apply !== false
    });
  }

  /* ── 5. Accessible Toast Live Region ─────────────────────────────────────── */

  function ensureToastContainer() {
    if (!hasDocument()) {
      return null;
    }
    if (state.toastContainer && document.contains(state.toastContainer)) {
      return state.toastContainer;
    }
    var existing = document.getElementById('hunter-toast-region');
    if (existing) {
      existing.setAttribute('aria-live', 'polite');
      existing.setAttribute('aria-relevant', 'additions text');
      state.toastContainer = existing;
      return existing;
    }
    var region = el('div', {
      id: 'hunter-toast-region',
      class: 'hunter-toast-region',
      role: 'region',
      'aria-live': 'polite',
      'aria-relevant': 'additions text',
      'aria-label': t('common.status', 'Notifications')
    });
    if (document.body) {
      document.body.appendChild(region);
    } else if (document.documentElement) {
      document.documentElement.appendChild(region);
    }
    state.toastContainer = region;
    return region;
  }

  function toast(msg, type, options) {
    var opts = options || {};
    var normalizedType =
      type === 'success' || type === 'warning' || type === 'error' ? type : 'info';
    var message = msg === null || msg === undefined ? '' : String(msg);
    if (!hasDocument()) {
      return { element: null, dismiss: function () {} };
    }
    var region = ensureToastContainer();
    var dismissed = false;
    var timerId = null;

    function dismiss() {
      if (dismissed) {
        return;
      }
      dismissed = true;
      if (timerId !== null) {
        clearTimeout(timerId);
        timerId = null;
      }
      if (toastNode.parentNode) {
        toastNode.parentNode.removeChild(toastNode);
      }
    }

    var closeBtn = el(
      'button',
      {
        type: 'button',
        class: 'hunter-toast-close',
        'aria-label': t('common.close', 'Close'),
        onclick: dismiss
      },
      '×'
    );

    var toastNode = el(
      'div',
      {
        class: 'hunter-toast',
        role: 'status',
        'data-type': normalizedType
      },
      [el('span', { class: 'hunter-toast-message' }, message), closeBtn]
    );

    region.appendChild(toastNode);

    var durationMs = typeof opts.durationMs === 'number' ? opts.durationMs : 4000;
    if (durationMs > 0) {
      timerId = setTimeout(dismiss, durationMs);
    }

    return {
      element: toastNode,
      dismiss: dismiss
    };
  }

  /* ── 6. Visibility-Aware AbortController Poller ────────────────────────── */

  function createVisibilityPoller(fn, intervalMs, options) {
    if (typeof fn !== 'function') {
      throw new TypeError('HunterCore.createVisibilityPoller requires a callback function');
    }
    var delay = Math.max(100, Number(intervalMs) || 5000);
    var opts = options || {};

    var running = false;
    var inFlight = false;
    var timerId = null;
    var activeController = null;
    var listenerAttached = false;

    function clearTimer() {
      if (timerId !== null) {
        clearTimeout(timerId);
        timerId = null;
      }
    }

    function abortInFlight(reason) {
      if (activeController) {
        try {
          activeController.abort(reason || 'aborted');
        } catch (_err) {
          activeController.abort();
        }
        activeController = null;
      }
    }

    function isPageHidden() {
      return hasDocument() && Boolean(document.hidden);
    }

    function scheduleNext() {
      clearTimer();
      if (!running || (isPageHidden() && !opts.runWhenHidden)) {
        return;
      }
      timerId = setTimeout(function () {
        timerId = null;
        runOnce();
      }, delay);
    }

    function runOnce() {
      if (!running) {
        return Promise.resolve();
      }
      if (isPageHidden() && !opts.runWhenHidden) {
        return Promise.resolve();
      }
      if (inFlight && !opts.allowOverlap) {
        return Promise.resolve();
      }
      abortInFlight('superseded');
      var controller = new AbortController();
      activeController = controller;
      inFlight = true;

      return Promise.resolve()
        .then(function () {
          return fn(controller.signal);
        })
        .catch(function (err) {
          if (err && err.name === 'AbortError') {
            return;
          }
          if (typeof opts.onError === 'function') {
            opts.onError(err);
          } else if (typeof console !== 'undefined' && console.error) {
            console.error('[HunterCore] poller error:', err);
          }
        })
        .finally(function () {
          if (activeController === controller) {
            activeController = null;
          }
          inFlight = false;
          scheduleNext();
        });
    }

    function onVisibilityChange() {
      if (!running) {
        return;
      }
      if (isPageHidden() && !opts.runWhenHidden) {
        clearTimer();
        abortInFlight('page-hidden');
      } else if (!isPageHidden()) {
        if (opts.immediateOnResume !== false) {
          runOnce();
        } else {
          scheduleNext();
        }
      }
    }

    function attachListener() {
      if (hasDocument() && !listenerAttached) {
        document.addEventListener('visibilitychange', onVisibilityChange);
        listenerAttached = true;
      }
    }

    function detachListener() {
      if (hasDocument() && listenerAttached) {
        document.removeEventListener('visibilitychange', onVisibilityChange);
        listenerAttached = false;
      }
    }

    function start(runImmediately) {
      if (running) {
        if (runImmediately) {
          return runOnce();
        }
        return Promise.resolve();
      }
      running = true;
      attachListener();
      if (runImmediately || opts.immediate) {
        return runOnce();
      }
      scheduleNext();
      return Promise.resolve();
    }

    function stop() {
      if (!running && !activeController && timerId === null) {
        return;
      }
      running = false;
      clearTimer();
      abortInFlight('poller-stopped');
      detachListener();
    }

    function trigger() {
      if (!running) {
        running = true;
        attachListener();
      }
      return runOnce();
    }

    function isRunning() {
      return running;
    }

    if (opts.autoStart !== false) {
      start(Boolean(opts.immediate));
    }

    return {
      start: start,
      stop: stop,
      trigger: trigger,
      isRunning: isRunning
    };
  }

  /* ── Auto-Sync on Browser Load ─────────────────────────────────────────── */

  if (hasDocument()) {
    setTheme(resolveInitialTheme(), { persist: Boolean(readQueryParam('theme')) });
    var initialLang = resolveInitialLang();
    state.lang = initialLang;
    applyLanguageAttributes(initialLang);

    if (hasWindow()) {
      window.addEventListener('storage', function (ev) {
        if (ev.key === THEME_STORAGE_KEY && ev.newValue && VALID_THEMES[ev.newValue]) {
          setTheme(ev.newValue, { persist: false });
        } else if (ev.key === LANG_STORAGE_KEY && ev.newValue && VALID_LANGS[ev.newValue]) {
          setLang(ev.newValue, { persist: false });
        }
      });
    }
  }

  var HunterCore = {
    version: '1.0.0',
    escapeHtml: escapeHtml,
    escapeAttr: escapeAttr,
    safeHref: safeHref,
    sanitizeHtml: sanitizeHtml,
    el: el,
    getTheme: getTheme,
    setTheme: setTheme,
    toggleTheme: toggleTheme,
    initTheme: initTheme,
    getLang: getLang,
    setLang: setLang,
    getCatalog: getCatalog,
    loadCatalog: loadCatalog,
    t: t,
    applyTranslations: applyTranslations,
    initI18n: initI18n,
    toast: toast,
    createVisibilityPoller: createVisibilityPoller
  };

  global.HunterCore = HunterCore;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = HunterCore;
  }
})(typeof window !== 'undefined' ? window : globalThis);
