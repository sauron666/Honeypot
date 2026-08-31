// MIRAGE operator console.
//
// Security invariant: every attacker-controlled string enters the DOM
// through textContent only. No innerHTML, no insertAdjacentHTML, no
// document.write. The server-side CSP is the second layer; this code
// is the first, and it is the one an attacker with shell access would
// actually test.

'use strict';

// ================================================================
// CONSTANTS
// ================================================================

var NAV = [
  { id: 'dashboard',   icon: '■', label: 'Dashboard' },
  { id: 'engagements', icon: '◆', label: 'Engagements' },
  { id: 'events',      icon: '≡', label: 'Events' },
  { id: 'decoys',      icon: '◎', label: 'Decoys & Services' },
  { id: 'tokens',      icon: '◇', label: 'Honeytokens' },
  { id: 'vms',         icon: '□', label: 'Full-OS VMs' },
  { id: 'images',      icon: '▤', label: 'Image Library' },
  { id: 'forge',       icon: '△', label: 'Detection Rules' },
  { id: 'evidence',    icon: '●', label: 'Evidence Chain' },
  { id: 'compliance',  icon: '✓', label: 'Compliance' },
  { id: 'observer',    icon: '◈', label: 'Observer / VMI' },
  { id: 'trap',        icon: '⊗', label: 'Ransomware Trap' },
  { id: 'topology',    icon: '⌘', label: 'Topology' },
  { id: 'presence',    icon: '⊕', label: 'Presence' },
  { id: 'packs',       icon: '❏', label: 'Deception Packs' },
  { id: 'identity',    icon: '⚿', label: 'Identity / BEC' },
  { id: 'wireless',    icon: '☊', label: 'BYOD / Wireless' },
  { id: 'feed',        icon: '⇄', label: 'Global Feed' },
  { id: 'alerting',    icon: '⚑', label: 'Alerting' },
  { id: 'config',      icon: '⊡', label: 'Configuration' },
  { id: 'about',       icon: '⊙', label: 'About / Status' },
];

var SEV_NAMES = ['', 'informational', 'low', 'medium', 'high', 'critical', 'fatal'];
var REFRESH_VIEWS = ['dashboard', 'engagements', 'events', 'presence', 'vms'];

// ================================================================
// STATE
// ================================================================

var S = {
  view: 'dashboard',
  live: true,
  timer: null,
  collapsed: false,
  tokenTypes: [],
  engagement: null,       // selected engagement id
  forgeEng: null,         // engagement id for forge view
  compFw: 'nis2',         // selected compliance framework
  evOffset: 0,            // events pagination offset
};

// ================================================================
// DOM UTILITIES
// ================================================================

var $ = function (id) { return document.getElementById(id); };

function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = String(text);
  return n;
}

function ago(ms) {
  var s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function fmtDate(t) {
  return new Date(t).toISOString().replace('T', ' ').replace(/\.\d+Z/, 'Z');
}

function sevName(id) { return SEV_NAMES[id] || 'low'; }
function sevCls(id) { return 'sev-' + sevName(id); }
function riskCls(s) { return s >= 70 ? 'risk-hi' : s >= 35 ? 'risk-md' : 'risk-lo'; }

function loading() {
  var d = el('div', 'loading-msg');
  d.appendChild(el('span', 'spinner'));
  d.appendChild(document.createTextNode(' Loading…'));
  return d;
}

function emptyState(text) { return el('div', 'empty-state', text); }
function emptyStateSm(text) { return el('div', 'empty-state empty-state-sm', text); }

// ================================================================
// TOAST
// ================================================================

var toastTimer;
function toast(msg, kind) {
  var t = $('toast');
  t.textContent = msg;
  t.className = 'toast' + (kind ? ' ' + kind : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { t.hidden = true; }, 6000);
}

// ================================================================
// MODAL
// ================================================================

var modalCb;
function confirmModal(title, message) {
  return new Promise(function (resolve) {
    modalCb = resolve;
    $('modal-title').textContent = title;
    $('modal-body').textContent = message;
    $('modal-overlay').hidden = false;
    $('modal').hidden = false;
  });
}
function closeModal(result) {
  $('modal-overlay').hidden = true;
  $('modal').hidden = true;
  if (modalCb) modalCb(result);
  modalCb = null;
}
$('modal-cancel').addEventListener('click', function () { closeModal(false); });
$('modal-ok').addEventListener('click', function () { closeModal(true); });
$('modal-overlay').addEventListener('click', function () { closeModal(false); });

// ================================================================
// DRAWER
// ================================================================

function openDrawer(title, buildFn) {
  $('drawer-title').textContent = title;
  var body = $('drawer-body');
  body.replaceChildren();
  buildFn(body);
  $('drawer-overlay').classList.add('visible');
  $('drawer').classList.add('open');
}
function closeDrawer() {
  $('drawer').classList.remove('open');
  $('drawer-overlay').classList.remove('visible');
}
$('drawer-close').addEventListener('click', closeDrawer);
$('drawer-overlay').addEventListener('click', closeDrawer);

// ================================================================
// API
// ================================================================

// --- auth: token is stored per-browser and sent as a Bearer header; it is also
// mirrored into a cookie so browser-driven downloads/navigations carry it. A
// tokenless deployment (loopback) just works; a tokened one prompts once. ---

function storedToken() {
  try { return localStorage.getItem('mirage_token') || ''; } catch (e) { return ''; }
}

function setToken(t) {
  try { localStorage.setItem('mirage_token', t); } catch (e) {}
  // Cookie so <a download>, window.open and image src carry the token too.
  document.cookie = 'mirage_token=' + encodeURIComponent(t) + '; path=/; SameSite=Strict';
}

function clearToken() {
  try { localStorage.removeItem('mirage_token'); } catch (e) {}
  document.cookie = 'mirage_token=; path=/; Max-Age=0; SameSite=Strict';
}

function authOpts(opts) {
  opts = opts || {};
  var t = storedToken();
  if (t) {
    var h = {};
    if (opts.headers) { for (var k in opts.headers) h[k] = opts.headers[k]; }
    h['Authorization'] = 'Bearer ' + t;
    opts.headers = h;
  }
  return opts;
}

function api(path, opts) {
  return fetch(path, authOpts(opts)).then(function (res) {
    if (res.status === 401) {
      showLogin();
      throw new Error('401 unauthorized — enter the API token');
    }
    if (!res.ok && res.status !== 503) {
      return res.text().then(function (t) {
        throw new Error(res.status + ' ' + t.slice(0, 200));
      });
    }
    return res.json();
  });
}

function apiText(path) {
  return fetch(path, authOpts()).then(function (res) {
    if (res.status === 401) { showLogin(); throw new Error('401 unauthorized'); }
    if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
    return res.text();
  });
}

// showLogin overlays a token prompt. Uses textContent/el() only (no innerHTML),
// and a button (not a native form submit — CSP form-action is 'none').
function showLogin() {
  if (document.getElementById('login-overlay')) return;
  var ov = el('div');
  ov.id = 'login-overlay';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;' +
    'display:flex;align-items:center;justify-content:center';
  var box = el('div', 'panel');
  box.style.cssText = 'width:360px;padding:22px';
  box.appendChild(el('div', 'panel-head', 'MIRAGE — API token required'));
  var body = el('div', 'panel-body padded');
  body.appendChild(el('div', 't-sec', 'This console requires the api.token from your profile.'));
  var input = el('input');
  input.type = 'password';
  input.placeholder = 'API token';
  input.style.cssText = 'width:100%;margin-top:12px;padding:8px;box-sizing:border-box';
  input.value = storedToken();
  body.appendChild(input);
  var btn = el('button', 'btn btn-primary', 'Unlock');
  btn.style.marginTop = '12px';
  var submit = function () {
    setToken(input.value.trim());
    ov.remove();
    loadStatus();
    renderView();
  };
  btn.addEventListener('click', submit);
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
  body.appendChild(btn);
  box.appendChild(body);
  ov.appendChild(box);
  document.body.appendChild(ov);
  input.focus();
}

function tryApi(path, opts) {
  return api(path, opts).catch(function () { return null; });
}

// ================================================================
// NAVIGATION & ROUTING
// ================================================================

function buildNav() {
  var nav = $('nav');
  nav.replaceChildren();
  NAV.forEach(function (item) {
    var btn = el('button', 'nav-item' + (item.id === S.view ? ' active' : ''));
    btn.appendChild(el('span', 'nav-icon', item.icon));
    btn.appendChild(el('span', 'nav-label', item.label));
    btn.addEventListener('click', function () { navigate(item.id); });
    nav.appendChild(btn);
  });
}

function navigate(view) {
  S.view = view;
  S.evOffset = 0;
  buildNav();
  var item = NAV.find(function (n) { return n.id === view; });
  $('page-title').textContent = item ? item.label : view;
  renderView();
}

// ---- Sidebar toggle ----
$('sidebar-toggle').addEventListener('click', function () {
  S.collapsed = !S.collapsed;
  $('sidebar').classList.toggle('collapsed', S.collapsed);
  document.body.classList.toggle('sb-collapsed', S.collapsed);
});

// ---- Live toggle ----
$('live-toggle').addEventListener('change', function (e) {
  S.live = e.target.checked;
  scheduleRefresh();
});

// ================================================================
// VIEW ROUTER
// ================================================================

var VIEWS = {
  dashboard:   viewDashboard,
  engagements: viewEngagements,
  events:      viewEvents,
  decoys:      viewDecoys,
  tokens:      viewTokens,
  vms:         viewVMs,
  images:      viewImages,
  forge:       viewForge,
  evidence:    viewEvidence,
  compliance:  viewCompliance,
  observer:    viewObserver,
  trap:        viewTrap,
  topology:    viewTopology,
  presence:    viewPresence,
  packs:       viewPacks,
  identity:    viewIdentity,
  wireless:    viewWireless,
  feed:        viewFeed,
  alerting:    viewAlerting,
  config:      viewConfig,
  about:       viewAbout,
};

function renderView() {
  var c = $('content');
  c.replaceChildren(loading());
  var fn = VIEWS[S.view];
  if (fn) fn(c).catch(function (e) {
    c.replaceChildren(el('div', 'empty-state', 'Error: ' + e.message));
    toast(e.message, 'err');
  });
}

// initTableSorting watches the content area and makes EVERY table sortable —
// including ones rebuilt dynamically (event filters, load-more, after an action)
// — with no per-view code. One observer instead of rewriting a dozen views.
function initTableSorting() {
  var content = $('content');
  if (!content || !window.MutationObserver) return;
  var obs = new MutationObserver(function (muts) {
    for (var i = 0; i < muts.length; i++) {
      var added = muts[i].addedNodes;
      for (var j = 0; j < added.length; j++) {
        var n = added[j];
        if (!n || n.nodeType !== 1) continue;
        if (n.matches && n.matches('table.tbl')) makeSortable(n);
        if (n.querySelectorAll) {
          var t = n.querySelectorAll('table.tbl');
          for (var k = 0; k < t.length; k++) makeSortable(t[k]);
        }
      }
    }
  });
  obs.observe(content, { childList: true, subtree: true });
}

function makeSortable(table) {
  if (!table.tHead || !table.tHead.rows.length) return;
  var ths = table.tHead.rows[0].cells;
  for (var i = 0; i < ths.length; i++) {
    (function (idx, th) {
      if (th.getAttribute('data-sortable') === '1') return;
      th.setAttribute('data-sortable', '1');
      th.classList.add('sortable');
      th.addEventListener('click', function () { sortByColumn(table, idx, th); });
    })(i, ths[i]);
  }
}

function sortByColumn(table, idx, th) {
  var tbody = table.tBodies[0];
  if (!tbody) return;
  var rows = Array.prototype.slice.call(tbody.rows);
  var asc = th.getAttribute('data-dir') !== 'asc';
  var ths = table.tHead.rows[0].cells;
  for (var j = 0; j < ths.length; j++) ths[j].removeAttribute('data-dir');
  th.setAttribute('data-dir', asc ? 'asc' : 'desc');
  rows.sort(function (a, b) {
    var x = cellText(a, idx), y = cellText(b, idx);
    var nx = numericLead(x), ny = numericLead(y);
    if (nx !== null && ny !== null) return asc ? nx - ny : ny - nx;
    return asc ? x.localeCompare(y) : y.localeCompare(x);
  });
  for (var k = 0; k < rows.length; k++) tbody.appendChild(rows[k]);
}

function cellText(row, idx) {
  var cell = row.cells[idx];
  return cell ? cell.textContent.trim() : '';
}

// numericLead returns a leading number ("23ms"->23, "#42"->42, "1.2s"->1.2) or
// null for text (so "critical" sorts alphabetically). Predictable, not clever.
function numericLead(s) {
  s = s.replace(/[,#$]/g, '').trim();
  if (!/^-?\d/.test(s)) return null;
  var f = parseFloat(s);
  return isNaN(f) ? null : f;
}

// ================================================================
// TOPBAR STATUS
// ================================================================

function loadStatus() {
  return api('/api/stats').then(function (s) {
    var bar = $('topbar-status');
    bar.replaceChildren();
    var add = function (label, val) {
      var sp = el('span', null, label + ' ');
      sp.appendChild(el('b', null, val));
      bar.appendChild(sp);
    };
    add('events', s.storage.events);
    add('active', s.engagements.active);
    add('sessions', s.live_sessions);
    add('alerts', s.alerts.sent);
    add('tokens', s.tokens.triggered + '/' + s.tokens.total);
    add('chain', '#' + s.storage.head_seq);
    add('uptime', s.uptime);
    add('', s.tenant + '/' + s.site);
  }).catch(function () {});
}

// ================================================================
// REFRESH
// ================================================================

function scheduleRefresh() {
  clearInterval(S.timer);
  if (S.live) {
    S.timer = setInterval(function () {
      loadStatus();
      if (REFRESH_VIEWS.indexOf(S.view) !== -1) renderView();
    }, 3000);
  }
}

// ================================================================
// HELPERS
// ================================================================

function panelHead(text, rightEl) {
  var h = el('div', 'panel-head');
  h.appendChild(document.createTextNode(text));
  if (rightEl) h.appendChild(rightEl);
  return h;
}

function kvRow(table, key, val) {
  if (!val && val !== 0) return;
  var tr = el('tr');
  tr.appendChild(el('td', 'k', key));
  var td = el('td');
  if (typeof val === 'string' && (val.length > 200 || val.indexOf('\n') !== -1)) {
    td.appendChild(el('pre', null, val));
  } else {
    td.textContent = String(val);
  }
  tr.appendChild(td);
  table.appendChild(tr);
}

function tagList(container, tags, cls) {
  (tags || []).forEach(function (t) {
    container.appendChild(el('span', 'tag' + (cls ? ' ' + cls : ''), t));
  });
}

function sparkline(events) {
  var now = Date.now();
  var counts = new Array(24).fill(0);
  var maxSev = new Array(24).fill(0);
  (events || []).forEach(function (ev) {
    var h = Math.floor((now - ev.time) / 3600000);
    if (h >= 0 && h < 24) {
      var idx = 23 - h;
      counts[idx]++;
      maxSev[idx] = Math.max(maxSev[idx], ev.severity_id || 0);
    }
  });
  var peak = Math.max.apply(null, counts) || 1;
  var wrap = el('div', 'sparkline');
  for (var i = 0; i < 24; i++) {
    var bar = el('div', 'spark-bar' + (counts[i] === 0 ? ' empty' : ''));
    bar.style.height = counts[i] ? Math.max(4, counts[i] / peak * 100) + '%' : '2px';
    if (maxSev[i] >= 5) bar.style.background = 'var(--sev-crit)';
    else if (maxSev[i] >= 4) bar.style.background = 'var(--sev-high)';
    else if (maxSev[i] >= 3) bar.style.background = 'var(--sev-med)';
    bar.title = counts[i] + ' events (' + (23 - i) + 'h ago)';
    wrap.appendChild(bar);
  }
  return wrap;
}

function highlightRule(content, format) {
  var pre = el('pre');
  content.split('\n').forEach(function (line) {
    if (line.match(/^\s*#/) || line.match(/^\s*\/\//)) {
      pre.appendChild(el('span', 'hl-cmt', line));
    } else if ((format === 'sigma' || format === 'yara') && line.match(/^\s*\w[\w\s]*:/)) {
      var ci = line.indexOf(':');
      pre.appendChild(el('span', 'hl-key', line.slice(0, ci + 1)));
      pre.appendChild(document.createTextNode(line.slice(ci + 1)));
    } else if (format === 'suricata' && line.match(/^(alert|drop|reject|pass)\s/)) {
      var si = line.indexOf(' ');
      pre.appendChild(el('span', 'hl-kw', line.slice(0, si)));
      pre.appendChild(document.createTextNode(line.slice(si)));
    } else {
      pre.appendChild(document.createTextNode(line));
    }
    pre.appendChild(document.createTextNode('\n'));
  });
  return pre;
}

function copyText(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(
      function () { toast('Copied to clipboard', 'ok'); },
      function () { toast('Copy failed', 'err'); }
    );
  }
}

// ================================================================
// VIEW: DASHBOARD
// ================================================================

function viewDashboard(c) {
  return Promise.all([
    api('/api/stats'),
    api('/api/engagements?limit=5'),
    api('/api/events?severity=high&limit=5'),
    api('/api/events?since_minutes=1440&limit=2000').catch(function () { return {events:[]}; }),
  ]).then(function (results) {
    var stats = results[0], engData = results[1], evHigh = results[2], act = results[3];
    c.replaceChildren();

    // ---- Stat cards ----
    var cards = el('div', 'cards-grid');
    var addCard = function (value, label, sub, cls) {
      var card = el('div', 'card');
      card.appendChild(el('div', 'card-value' + (cls ? ' ' + cls : ''), value));
      card.appendChild(el('div', 'card-label', label));
      if (sub) card.appendChild(el('div', 'card-sub', sub));
      cards.appendChild(card);
    };
    addCard(stats.storage.events, 'Total Events');
    addCard(stats.engagements.active, 'Active Engagements',
      stats.engagements.closed + ' closed',
      stats.engagements.active > 0 ? 't-crit' : '');
    addCard(stats.live_sessions, 'Live Sessions', null,
      stats.live_sessions > 0 ? 't-high' : '');
    addCard(stats.alerts.sent, 'Alerts Sent',
      stats.alerts.suppressed + ' deduped');
    addCard(stats.tokens.triggered + '/' + stats.tokens.total, 'Honeytokens',
      stats.tokens.triggered > 0 ? 'TRIGGERED' : 'all quiet',
      stats.tokens.triggered > 0 ? 't-crit' : '');
    addCard('#' + stats.storage.head_seq, 'Chain Head',
      stats.storage.head_hash ? stats.storage.head_hash.slice(0, 16) : '');
    c.appendChild(cards);

    // ---- Two-column panels ----
    var grid = el('div', 'section-grid');

    // Threat activity sparkline
    var sparkP = el('div', 'panel');
    sparkP.appendChild(panelHead('Threat Activity (24h)'));
    var sparkB = el('div', 'panel-body padded');
    sparkB.appendChild(sparkline(act.events));
    var legend = el('div', 't-muted');
    legend.style.fontSize = '10px';
    legend.style.marginTop = '6px';
    legend.textContent = '24h ago ← → now  |  Bar height = event count, color = max severity';
    sparkB.appendChild(legend);
    sparkP.appendChild(sparkB);
    grid.appendChild(sparkP);

    // Active engagements
    var engP = el('div', 'panel');
    engP.appendChild(panelHead('Active Engagements'));
    var engB = el('div', 'panel-body');
    var active = (engData.engagements || []).filter(function (e) { return e.active; }).slice(0, 5);
    if (!active.length) {
      engB.appendChild(emptyStateSm('No active engagements. Decoys are listening.'));
    } else {
      active.forEach(function (e) {
        var row = el('div', 'list-row');
        row.addEventListener('click', function () { S.engagement = e.id; navigate('engagements'); });
        var sv = el('span', 'sev-bar ' + sevCls(e.max_severity));
        row.appendChild(sv);
        var main = el('div', 'list-row-main');
        var top = el('div', 'list-row-top');
        var title = el('span', 'list-row-title');
        if (e.active) {
          var badge = el('span', 'badge-live', ' live');
          title.textContent = e.src_ip + ' ';
          title.appendChild(badge);
        } else {
          title.textContent = e.src_ip;
        }
        top.appendChild(title);
        top.appendChild(el('span', 'list-row-time', ago(Date.parse(e.last_seen))));
        main.appendChild(top);
        main.appendChild(el('div', 'list-row-meta', e.summary || 'contact with a decoy'));
        row.appendChild(main);
        row.appendChild(el('span', 'risk ' + riskCls(e.risk_score), e.risk_score));
        engB.appendChild(row);
      });
    }
    engP.appendChild(engB);
    grid.appendChild(engP);

    // Recent high-severity events
    var evP = el('div', 'panel');
    evP.appendChild(panelHead('Recent High-Severity Events'));
    var evB = el('div', 'panel-body');
    var evs = (evHigh.events || []).slice(0, 5);
    if (!evs.length) {
      evB.appendChild(emptyStateSm('No high-severity events.'));
    } else {
      evs.forEach(function (ev) {
        var row = el('div', 'list-row');
        row.addEventListener('click', function () { showEventDrawer(ev); });
        row.appendChild(el('span', 'sev-bar ' + sevCls(ev.severity_id)));
        var main = el('div', 'list-row-main');
        var top = el('div', 'list-row-top');
        top.appendChild(el('span', 'list-row-title', ev.message || ev.class_uid));
        top.appendChild(el('span', 'list-row-time', ago(ev.time)));
        main.appendChild(top);
        var meta = el('div', 'list-row-tags');
        meta.appendChild(el('span', 'tag', ev.mirage.service || 'system'));
        if (ev.src_endpoint) meta.appendChild(el('span', 'tag', ev.src_endpoint.ip));
        main.appendChild(meta);
        row.appendChild(main);
        evB.appendChild(row);
      });
    }
    evP.appendChild(evB);
    grid.appendChild(evP);

    // System health
    var hlP = el('div', 'panel');
    hlP.appendChild(panelHead('System Health'));
    var hlB = el('div', 'panel-body padded');
    var ht = el('table', 'kv');
    kvRow(ht, 'version', stats.version);
    kvRow(ht, 'uptime', stats.uptime);
    kvRow(ht, 'tenant / site', stats.tenant + ' / ' + stats.site);
    kvRow(ht, 'events stored', stats.storage.events);
    kvRow(ht, 'chain head', '#' + stats.storage.head_seq);
    kvRow(ht, 'engagements', stats.engagements.active + ' active, ' + stats.engagements.closed + ' closed');
    kvRow(ht, 'alerts', stats.alerts.sent + ' sent, ' + stats.alerts.suppressed + ' deduped, ' + stats.alerts.failed + ' failed');
    hlB.appendChild(ht);
    hlP.appendChild(hlB);
    grid.appendChild(hlP);

    c.appendChild(grid);
  });
}

// ================================================================
// VIEW: ENGAGEMENTS
// ================================================================

function viewEngagements(c) {
  return api('/api/engagements?limit=200').then(function (data) {
    c.replaceChildren();
    var engs = data.engagements || [];

    // Filters
    var filters = el('div', 'filters');
    var fIP = el('input', 'f-input');
    fIP.type = 'search'; fIP.placeholder = 'Search source IP…';
    var fStatus = el('select', 'f-select');
    fStatus.appendChild(new Option('All', 'all'));
    fStatus.appendChild(new Option('Active', 'active'));
    fStatus.appendChild(new Option('Closed', 'closed'));
    var fSev = el('select', 'f-select');
    fSev.appendChild(new Option('Any severity', ''));
    fSev.appendChild(new Option('Critical', '5'));
    fSev.appendChild(new Option('High+', '4'));
    fSev.appendChild(new Option('Medium+', '3'));
    filters.appendChild(fIP);
    filters.appendChild(fStatus);
    filters.appendChild(fSev);
    c.appendChild(filters);

    // Table
    var panel = el('div', 'panel');
    var tbl = el('table', 'tbl');
    var thead = el('thead');
    var hr = el('tr');
    ['', 'Source IP', 'Risk', 'Severity', 'Services', 'Techniques', 'Duration', 'Status'].forEach(function (h) {
      hr.appendChild(el('th', null, h));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);
    var tbody = el('tbody');
    tbl.appendChild(tbody);
    panel.appendChild(tbl);
    c.appendChild(panel);

    function renderRows() {
      tbody.replaceChildren();
      var ipFilter = fIP.value.toLowerCase().trim();
      var stFilter = fStatus.value;
      var sevFilter = parseInt(fSev.value) || 0;

      var filtered = engs.filter(function (e) {
        if (ipFilter && e.src_ip.toLowerCase().indexOf(ipFilter) === -1) return false;
        if (stFilter === 'active' && !e.active) return false;
        if (stFilter === 'closed' && e.active) return false;
        if (sevFilter && (e.max_severity || 0) < sevFilter) return false;
        return true;
      });

      if (!filtered.length) {
        var emptyTr = el('tr');
        var emptyTd = el('td');
        emptyTd.colSpan = 8;
        emptyTd.appendChild(emptyStateSm('No engagements match the filter.'));
        emptyTr.appendChild(emptyTd);
        tbody.appendChild(emptyTr);
        return;
      }

      filtered.forEach(function (e) {
        var tr = el('tr', 'clickable' + (S.engagement === e.id ? ' selected' : ''));
        // severity bar
        var sevTd = el('td', 'narrow');
        sevTd.appendChild(el('span', 'sev-bar ' + sevCls(e.max_severity)));
        tr.appendChild(sevTd);
        // IP
        tr.appendChild(el('td', null, e.src_ip));
        // risk
        var rTd = el('td');
        rTd.appendChild(el('span', 'risk ' + riskCls(e.risk_score), e.risk_score));
        tr.appendChild(rTd);
        // severity
        tr.appendChild(el('td', null, sevName(e.max_severity)));
        // services
        var sTd = el('td');
        tagList(sTd, e.services);
        tr.appendChild(sTd);
        // techniques
        var tTd = el('td');
        tagList(tTd, (e.techniques || []).slice(0, 3), 'tag-att');
        tr.appendChild(tTd);
        // duration
        tr.appendChild(el('td', 'narrow', ago(Date.parse(e.last_seen))));
        // status
        var stTd = el('td', 'narrow');
        if (e.active) {
          stTd.appendChild(el('span', 'badge-live', 'live'));
        } else {
          stTd.appendChild(el('span', 't-muted', 'closed'));
        }
        tr.appendChild(stTd);

        tr.addEventListener('click', function () {
          S.engagement = e.id;
          showEngagementDrawer(e);
        });
        tbody.appendChild(tr);
      });
    }

    fIP.addEventListener('input', renderRows);
    fStatus.addEventListener('change', renderRows);
    fSev.addEventListener('change', renderRows);
    renderRows();

    // Auto-open if we navigated here with an engagement selected
    if (S.engagement) {
      var found = engs.find(function (e) { return e.id === S.engagement; });
      if (found) showEngagementDrawer(found);
    }
  });
}

function showEngagementDrawer(eng) {
  openDrawer('Engagement: ' + eng.src_ip, function (body) {
    body.appendChild(loading());

    Promise.all([
      api('/api/engagements/' + encodeURIComponent(eng.id) + '/events?limit=500'),
      tryApi('/api/economics'),
    ]).then(function (results) {
      var evData = results[0], econ = results[1];
      body.replaceChildren();

      // Summary
      body.appendChild(el('h3', null, 'Summary'));
      var st = el('table', 'kv');
      kvRow(st, 'engagement', eng.id);
      kvRow(st, 'source IP', eng.src_ip);
      kvRow(st, 'risk score', eng.risk_score);
      kvRow(st, 'severity', sevName(eng.max_severity));
      kvRow(st, 'status', eng.active ? 'ACTIVE' : 'closed');
      kvRow(st, 'last seen', fmtDate(eng.last_seen));
      kvRow(st, 'summary', eng.summary);
      body.appendChild(st);

      // Services
      if (eng.services && eng.services.length) {
        body.appendChild(el('h3', null, 'Services Touched'));
        var sd = el('div');
        tagList(sd, eng.services);
        body.appendChild(sd);
      }

      // ATT&CK techniques
      if (eng.techniques && eng.techniques.length) {
        body.appendChild(el('h3', null, 'ATT&CK Techniques'));
        var td = el('div');
        tagList(td, eng.techniques, 'tag-att');
        body.appendChild(td);
      }

      // Honeytokens hit
      if (eng.honeytokens_hit && eng.honeytokens_hit.length) {
        body.appendChild(el('h3', null, 'Honeytokens Triggered'));
        var tkd = el('div');
        tagList(tkd, eng.honeytokens_hit.map(function (t) { return 'token:' + t; }), 'tag-tok');
        body.appendChild(tkd);
      }

      // Economics
      if (econ) {
        body.appendChild(el('h3', null, 'Economics'));
        var ecT = el('table', 'kv');
        if (econ.total_attacker_seconds != null) {
          kvRow(ecT, 'attacker time burned', Math.round(econ.total_attacker_seconds / 60) + ' min');
        }
        if (econ.total_engagements != null) {
          kvRow(ecT, 'total engagements', econ.total_engagements);
        }
        body.appendChild(ecT);
      }

      // Timeline
      body.appendChild(el('h3', null, 'Timeline (' + (evData.events || []).length + ' events)'));
      var evs = evData.events || [];
      if (!evs.length) {
        body.appendChild(emptyStateSm('No events recorded.'));
      } else {
        evs.forEach(function (ev) {
          var row = el('div', 'list-row');
          row.addEventListener('click', function (e) { e.stopPropagation(); showEventDrawer(ev); });
          row.appendChild(el('span', 'sev-bar ' + sevCls(ev.severity_id)));
          var main = el('div', 'list-row-main');
          var top = el('div', 'list-row-top');
          top.appendChild(el('span', 'list-row-title', ev.message || ev.class_uid));
          top.appendChild(el('span', 'list-row-time', fmtDate(ev.time)));
          main.appendChild(top);
          var tags = el('div', 'list-row-tags');
          tags.appendChild(el('span', 'tag', ev.mirage.service || 'system'));
          (ev.mirage.attack || []).forEach(function (a) {
            tags.appendChild(el('span', 'tag tag-att', a.technique + (a.name ? ' ' + a.name : '')));
          });
          main.appendChild(tags);
          row.appendChild(main);
          body.appendChild(row);
        });
      }

      // Actions
      body.appendChild(el('h3', null, 'Actions'));
      var actions = el('div', 'detail-actions');
      var forgeBtn = el('button', 'btn btn-secondary', 'Generate Detection Rules');
      forgeBtn.addEventListener('click', function () {
        closeDrawer();
        S.forgeEng = eng.id;
        navigate('forge');
      });
      actions.appendChild(forgeBtn);

      var stixBtn = el('button', 'btn btn-secondary', 'Export STIX Bundle');
      stixBtn.addEventListener('click', function () {
        window.open('/api/engagements/' + encodeURIComponent(eng.id) + '/forge?format=stix', '_blank', 'noopener');
      });
      actions.appendChild(stixBtn);

      var reportBtn = el('button', 'btn btn-secondary', 'Incident Report');
      reportBtn.addEventListener('click', function () {
        window.open('/api/engagements/' + encodeURIComponent(eng.id) + '/forge?format=report', '_blank', 'noopener');
      });
      actions.appendChild(reportBtn);

      // Offline analyst narrative (template — deterministic, requires review).
      var aiBtn = el('button', 'btn btn-secondary', 'Analyst Narrative');
      aiBtn.addEventListener('click', function () {
        aiBtn.disabled = true; aiBtn.textContent = 'Analysing…';
        api('/api/analyst/' + encodeURIComponent(eng.id)).then(function (n) {
          aiBtn.disabled = false; aiBtn.textContent = 'Analyst Narrative';
          var box = document.getElementById('analyst-box') || el('div');
          box.id = 'analyst-box'; box.replaceChildren();
          box.style.marginTop = '12px';
          box.appendChild(el('div', 't-muted', 'source: ' + (n.source || 'template') +
            (n.requires_review ? ' — requires human review' : '')));
          box.appendChild(el('pre', 'config-block', n.report_draft || n.summary || ''));
          body.appendChild(box);
        }).catch(function (e) {
          aiBtn.disabled = false; aiBtn.textContent = 'Analyst Narrative';
          toast(e.message, 'err');
        });
      });
      actions.appendChild(aiBtn);
      body.appendChild(actions);
    }).catch(function (err) {
      body.replaceChildren(el('div', 'empty-state', 'Failed to load: ' + err.message));
    });
  });
}

// ================================================================
// VIEW: EVENTS
// ================================================================

function viewEvents(c) {
  c.replaceChildren();

  // Filters
  var filters = el('div', 'filters');
  var fQ = el('input', 'f-input');
  fQ.type = 'search'; fQ.placeholder = 'Search commands, paths, payloads, IPs…';
  var fSev = el('select', 'f-select');
  fSev.appendChild(new Option('Any severity', ''));
  fSev.appendChild(new Option('Low+', 'low'));
  fSev.appendChild(new Option('Medium+', 'medium'));
  fSev.appendChild(new Option('High+', 'high'));
  fSev.appendChild(new Option('Critical', 'critical'));
  var fSvc = el('input', 'f-input');
  fSvc.type = 'text'; fSvc.placeholder = 'Service filter…'; fSvc.style.maxWidth = '140px';
  filters.appendChild(fQ);
  filters.appendChild(fSev);
  filters.appendChild(fSvc);

  if (S.engagement) {
    var clearBtn = el('button', 'btn btn-sm btn-ghost', 'Clear engagement filter');
    clearBtn.addEventListener('click', function () {
      S.engagement = null;
      viewEvents(c);
    });
    filters.appendChild(clearBtn);
  }
  c.appendChild(filters);

  // Container for event list
  var panel = el('div', 'panel');
  var listC = el('div', 'panel-body');
  listC.style.maxHeight = 'none';
  panel.appendChild(listC);
  c.appendChild(panel);

  // Load more button
  var loadMoreBtn = el('button', 'btn btn-secondary btn-sm');
  loadMoreBtn.textContent = 'Load more';
  loadMoreBtn.style.marginTop = '12px';
  loadMoreBtn.hidden = true;
  c.appendChild(loadMoreBtn);

  var debounceTimer;
  function loadEvents() {
    var params = new URLSearchParams();
    params.set('limit', '100');
    params.set('offset', String(S.evOffset));
    var q = fQ.value.trim();
    if (q) params.set('q', q);
    var sev = fSev.value;
    if (sev) params.set('severity', sev);
    var svc = fSvc.value.trim();
    if (svc) params.set('service', svc);

    var url;
    if (S.engagement) {
      url = '/api/engagements/' + encodeURIComponent(S.engagement) + '/events?' + params;
    } else {
      url = '/api/events?' + params;
    }

    listC.replaceChildren(loading());
    return api(url).then(function (data) {
      listC.replaceChildren();
      var evs = data.events || [];
      loadMoreBtn.hidden = evs.length < 100;

      if (!evs.length) {
        listC.appendChild(emptyState('No events match the filter.'));
        return;
      }

      // Build table
      var tbl = el('table', 'tbl');
      var thead = el('thead');
      var hr = el('tr');
      ['', 'Time', 'Severity', 'Service', 'Source IP', 'Decoy', 'Message'].forEach(function (h) {
        hr.appendChild(el('th', null, h));
      });
      thead.appendChild(hr);
      tbl.appendChild(thead);
      var tbody = el('tbody');

      evs.forEach(function (ev) {
        var tr = el('tr', 'clickable');
        var sevTd = el('td', 'narrow');
        sevTd.appendChild(el('span', 'sev-bar ' + sevCls(ev.severity_id)));
        tr.appendChild(sevTd);
        tr.appendChild(el('td', 'narrow', fmtDate(ev.time)));
        tr.appendChild(el('td', 'narrow', sevName(ev.severity_id)));
        tr.appendChild(el('td', 'narrow', ev.mirage.service || '-'));
        tr.appendChild(el('td', 'narrow', ev.src_endpoint ? ev.src_endpoint.ip : '-'));
        tr.appendChild(el('td', 'narrow', ev.mirage.decoy_id || '-'));
        var msgTd = el('td', 'truncate', ev.message || ev.class_uid);
        tr.appendChild(msgTd);
        tr.addEventListener('click', function () { showEventDrawer(ev); });
        tbody.appendChild(tr);
      });

      tbl.appendChild(tbody);
      listC.appendChild(tbl);
    });
  }

  fQ.addEventListener('input', function () {
    clearTimeout(debounceTimer);
    S.evOffset = 0;
    debounceTimer = setTimeout(function () { loadEvents().catch(function (e) { toast(e.message, 'err'); }); }, 300);
  });
  fSev.addEventListener('change', function () { S.evOffset = 0; loadEvents().catch(function (e) { toast(e.message, 'err'); }); });
  fSvc.addEventListener('input', function () {
    clearTimeout(debounceTimer);
    S.evOffset = 0;
    debounceTimer = setTimeout(function () { loadEvents().catch(function (e) { toast(e.message, 'err'); }); }, 300);
  });
  loadMoreBtn.addEventListener('click', function () {
    S.evOffset += 100;
    loadEvents().catch(function (e) { toast(e.message, 'err'); });
  });

  return loadEvents();
}

// ================================================================
// EVENT DETAIL DRAWER
// ================================================================

function showEventDrawer(ev) {
  openDrawer(ev.message || ev.class_uid, function (body) {
    body.appendChild(el('h3', null, 'Event'));
    var t = el('table', 'kv');
    kvRow(t, 'time', fmtDate(ev.time));
    kvRow(t, 'severity', sevName(ev.severity_id));
    kvRow(t, 'class', ev.class_uid);
    kvRow(t, 'plane', ev.mirage.source_plane);
    kvRow(t, 'decoy', ev.mirage.decoy_id);
    kvRow(t, 'persona', ev.mirage.decoy_persona);
    kvRow(t, 'service', ev.mirage.service);
    kvRow(t, 'engagement', ev.mirage.engagement_id);
    if (ev.src_endpoint) {
      kvRow(t, 'source', ev.src_endpoint.ip + ':' + ev.src_endpoint.port);
    }
    if (ev.dst_endpoint) {
      kvRow(t, 'destination', ev.dst_endpoint.ip + ':' + ev.dst_endpoint.port);
    }
    if (ev.mirage.chain) {
      kvRow(t, 'chain seq', ev.mirage.chain.seq);
      kvRow(t, 'chain hash', ev.mirage.chain.hash);
    }
    kvRow(t, 'event uid', ev.metadata.uid);
    body.appendChild(t);

    // ATT&CK
    if (ev.mirage.attack && ev.mirage.attack.length) {
      body.appendChild(el('h3', null, 'ATT&CK'));
      var ad = el('div');
      ev.mirage.attack.forEach(function (a) {
        var text = (a.tactic || '') + ' ' + a.technique + ' ' + (a.name || '');
        ad.appendChild(el('span', 'tag tag-att', text.trim()));
      });
      body.appendChild(ad);
    }

    // Transcript
    var data = ev.unmapped || {};
    if (data.transcript) {
      body.appendChild(el('h3', null, 'Session Transcript'));
      body.appendChild(el('pre', null, data.transcript));
    }

    // Other unmapped data
    var rest = Object.entries(data).filter(function (kv) { return kv[0] !== 'transcript'; });
    if (rest.length) {
      body.appendChild(el('h3', null, 'Details'));
      var dt = el('table', 'kv');
      rest.forEach(function (pair) {
        var val = typeof pair[1] === 'string' ? pair[1] : JSON.stringify(pair[1], null, 2);
        kvRow(dt, pair[0], val);
      });
      body.appendChild(dt);
    }

    // Actions
    if (ev.mirage.engagement_id) {
      body.appendChild(el('h3', null, 'Actions'));
      var actions = el('div', 'detail-actions');
      var viewEngBtn = el('button', 'btn btn-sm btn-secondary', 'View Engagement');
      viewEngBtn.addEventListener('click', function () {
        closeDrawer();
        S.engagement = ev.mirage.engagement_id;
        navigate('engagements');
      });
      actions.appendChild(viewEngBtn);
      body.appendChild(actions);
    }
  });
}

// ================================================================
// VIEW: DECOYS & SERVICES
// ================================================================

function viewDecoys(c) {
  return Promise.all([api('/api/decoys'), tryApi('/api/services')]).then(function (res) {
    var data = res[0];
    var cat = res[1] || { services: [], personas: [] };
    c.replaceChildren();
    var bound = data.bound || [];
    var personas = data.personas || {};

    // ---- Decoy builder (add / edit) ----
    // The same reconcile path as the Config manifest, driven by a form: the
    // running set, plus this decoy (replacing one with the same id).
    c.appendChild(decoyBuilder(c, cat));

    // Group by decoy
    var byDecoy = new Map();
    bound.forEach(function (l) {
      if (!byDecoy.has(l.decoy_id)) byDecoy.set(l.decoy_id, []);
      byDecoy.get(l.decoy_id).push(l);
    });

    if (!byDecoy.size) {
      c.appendChild(emptyState('No decoys are listening yet. Build one above.'));
      return;
    }

    // Summary bar
    var summary = el('div', 'filters');
    summary.style.marginTop = '16px';
    summary.appendChild(el('span', 't-sec',
      byDecoy.size + ' decoys  |  ' + bound.length + ' listeners  |  ' +
      data.projected_addresses + ' projected addresses'));
    c.appendChild(summary);

    var grid = el('div', 'decoy-grid');
    byDecoy.forEach(function (listeners, decoyID) {
      var persona = listeners[0].persona;
      var info = personas[persona] || {};

      var card = el('div', 'decoy-card');
      var head = el('div', 'decoy-card-head');
      head.appendChild(el('span', null, decoyID));
      var headR = el('span', 't-muted');
      headR.textContent = info.hostname || persona;
      head.appendChild(headR);
      card.appendChild(head);

      var body = el('div', 'decoy-card-body');
      var kt = el('table', 'kv');
      kvRow(kt, 'persona', persona);
      kvRow(kt, 'hostname', info.hostname);
      kvRow(kt, 'os', info.os);
      kvRow(kt, 'uptime', info.uptime_days ? info.uptime_days + ' days' : '-');
      kvRow(kt, 'users', info.users);
      body.appendChild(kt);

      var svcs = el('div', 'decoy-services');
      listeners.forEach(function (l) {
        svcs.appendChild(el('span', 'tag tag-accent', l.service + ' ' + l.address + '/' + l.proto));
      });
      body.appendChild(svcs);

      // Retire: drops this decoy's listeners and reconciles. Emulated listeners
      // are not evidence, so this is safe (a full-OS VM decoy is not).
      var foot = el('div', 'decoy-card-foot');
      var retire = el('button', 'btn-link t-err', 'retire');
      retire.addEventListener('click', function () {
        confirmModal('Retire decoy',
          'Stop and remove decoy "' + decoyID + '" (' + listeners.length + ' listeners)? ' +
          'Evidence already collected is kept.').then(function (ok) {
          if (!ok) return;
          api('/api/decoys/' + encodeURIComponent(decoyID), { method: 'DELETE' }).then(function () {
            toast('Retired ' + decoyID, 'ok');
            viewDecoys(c).catch(function (e) { toast(e.message, 'err'); });
          }).catch(function (e) { toast(e.message, 'err'); });
        });
      });
      foot.appendChild(retire);
      body.appendChild(foot);

      card.appendChild(body);
      grid.appendChild(card);
    });
    c.appendChild(grid);
  });
}

// decoyBuilder is the add/edit form: an identity, optional projection
// addresses, and one or more services. Deploying an id that already exists
// edits it in place (the server merges by id).
function decoyBuilder(c, cat) {
  var panel = el('div', 'panel');
  panel.appendChild(panelHead('Build a Decoy',
    el('span', 't-muted', 'add or edit — deploying an existing id replaces it')));
  var body = el('div', 'panel-body padded');

  var row1 = el('div', 'form-row');
  var idG = el('div', 'form-group grow');
  idG.appendChild(el('label', 'form-label', 'Decoy id'));
  var idInp = el('input', 'f-input'); idInp.placeholder = 'e.g. db-prod-2';
  idG.appendChild(idInp); row1.appendChild(idG);

  var pG = el('div', 'form-group grow');
  pG.appendChild(el('label', 'form-label', 'Persona'));
  var pSel = el('select', 'f-select');
  (cat.personas || []).forEach(function (p) { pSel.appendChild(new Option(p, p)); });
  pG.appendChild(pSel); row1.appendChild(pG);

  var aG = el('div', 'form-group grow');
  aG.appendChild(el('label', 'form-label', 'Addresses (optional, comma-separated)'));
  var aInp = el('input', 'f-input');
  aInp.placeholder = 'blank = farm bind; e.g. 192.168.1.150 (must exist on host)';
  aInp.title = 'Pin this decoy to one or more IPs so it answers there instead of the console address. Each must already be on the host (ip addr add ...).';
  aG.appendChild(aInp); row1.appendChild(aG);
  body.appendChild(row1);

  // Dynamic service rows.
  var svcWrap = el('div'); svcWrap.style.marginTop = '10px';
  body.appendChild(el('label', 'form-label', 'Services'));
  body.appendChild(svcWrap);

  function addSvcRow(preset) {
    var r = el('div', 'form-row'); r.style.marginTop = '6px';
    var sSel = el('select', 'f-select');
    (cat.services || []).forEach(function (s) { sSel.appendChild(new Option(s, s)); });
    if (preset && preset.service) sSel.value = preset.service;
    var portInp = el('input', 'f-input'); portInp.type = 'number'; portInp.placeholder = 'port';
    portInp.style.maxWidth = '110px';
    if (preset && preset.port) portInp.value = preset.port;
    var protoSel = el('select', 'f-select'); protoSel.style.maxWidth = '110px';
    ['auto', 'tcp', 'udp'].forEach(function (p) { protoSel.appendChild(new Option(p, p === 'auto' ? '' : p)); });
    var rm = el('button', 'btn-link t-err', '×');
    rm.addEventListener('click', function () { r.remove(); });
    r.appendChild(sSel); r.appendChild(portInp); r.appendChild(protoSel); r.appendChild(rm);
    r._read = function () {
      return { service: sSel.value, port: parseInt(portInp.value, 10) || 0, protocol: protoSel.value };
    };
    svcWrap.appendChild(r);
  }
  addSvcRow({ service: 'ssh', port: 22 });

  var ctrlRow = el('div', 'form-row'); ctrlRow.style.marginTop = '10px';
  var addSvcBtn = el('button', 'btn btn-secondary', '+ service');
  addSvcBtn.addEventListener('click', function () { addSvcRow(); });
  var deployBtn = el('button', 'btn btn-primary', 'Deploy decoy');
  deployBtn.addEventListener('click', function () {
    var id = idInp.value.trim();
    if (!id) { toast('A decoy id is required', 'err'); return; }
    var services = [];
    Array.prototype.forEach.call(svcWrap.children, function (r) {
      if (r._read) { var s = r._read(); if (s.service && s.port) services.push(s); }
    });
    if (!services.length) { toast('Add at least one service with a port', 'err'); return; }
    var addresses = aInp.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    deployBtn.disabled = true;
    api('/api/decoys', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id, persona: pSel.value, addresses: addresses, services: services }),
    }).then(function () {
      toast('Deployed decoy ' + id, 'ok');
      viewDecoys(c).catch(function (e) { toast(e.message, 'err'); });
    }).catch(function (e) { deployBtn.disabled = false; toast(e.message, 'err'); });
  });
  ctrlRow.appendChild(addSvcBtn); ctrlRow.appendChild(deployBtn);
  body.appendChild(ctrlRow);

  panel.appendChild(body);
  return panel;
}

// ================================================================
// VIEW: HONEYTOKENS
// ================================================================

function viewTokens(c) {
  return api('/api/tokens').then(function (data) {
    c.replaceChildren();

    // Populate types
    if (data.types && data.types.length) S.tokenTypes = data.types;

    // ---- Mint form ----
    var formPanel = el('div', 'panel');
    formPanel.appendChild(panelHead('Mint a New Honeytoken'));
    var formBody = el('div', 'panel-body padded');
    var row = el('div', 'form-row');

    var tGroup = el('div', 'form-group');
    tGroup.appendChild(el('label', 'form-label', 'Type'));
    var tSel = el('select', 'f-select');
    S.tokenTypes.forEach(function (t) { tSel.appendChild(new Option(t, t)); });
    tGroup.appendChild(tSel);
    row.appendChild(tGroup);

    var lGroup = el('div', 'form-group grow');
    lGroup.appendChild(el('label', 'form-label', 'Label'));
    var lInp = el('input', 'f-input');
    lInp.placeholder = 'e.g. finance share key';
    lGroup.appendChild(lInp);
    row.appendChild(lGroup);

    var locGroup = el('div', 'form-group grow');
    locGroup.appendChild(el('label', 'form-label', 'Location'));
    var locInp = el('input', 'f-input');
    locInp.placeholder = 'where you will plant it';
    locGroup.appendChild(locInp);
    row.appendChild(locGroup);

    var mintBtn = el('button', 'btn btn-primary', 'Mint');
    mintBtn.style.alignSelf = 'flex-end';
    mintBtn.addEventListener('click', function () {
      var type = tSel.value;
      if (!type) return;
      api('/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: type,
          label: lInp.value.trim(),
          location: locInp.value.trim(),
        }),
      }).then(function () {
        lInp.value = ''; locInp.value = '';
        toast('Minted a ' + type + ' token. Plant it and wait.', 'ok');
        viewTokens(c).catch(function (e) { toast(e.message, 'err'); });
      }).catch(function (e) { toast(e.message, 'err'); });
    });
    row.appendChild(mintBtn);
    formBody.appendChild(row);
    formPanel.appendChild(formBody);
    c.appendChild(formPanel);

    // ---- Stats ----
    var statsLine = el('div', 't-sec');
    statsLine.style.margin = '16px 0 12px';
    statsLine.textContent = (data.total || 0) + ' tokens total, ' +
      (data.triggered || 0) + ' triggered (' +
      (data.total ? Math.round(data.triggered / data.total * 100) : 0) + '%)';
    c.appendChild(statsLine);

    // ---- Token list ----
    var tokens = data.tokens || [];
    if (!tokens.length) {
      c.appendChild(emptyState('No honeytokens yet. Mint one above and plant it.'));
      return;
    }

    var panel = el('div', 'panel');
    var tbl = el('table', 'tbl');
    var thead = el('thead');
    var hr = el('tr');
    ['Type', 'Label', 'Value', 'Location', 'Status', 'Triggers', 'Actions'].forEach(function (h) {
      hr.appendChild(el('th', null, h));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    var tbody = el('tbody');
    tokens.forEach(function (tk) {
      var tr = el('tr');
      tr.appendChild(el('td', 'narrow', tk.type));
      tr.appendChild(el('td', null, tk.label || '-'));
      var valTd = el('td', 'truncate t-muted');
      valTd.style.maxWidth = '180px'; valTd.style.fontSize = '11px';
      valTd.textContent = tk.value || tk.id;
      valTd.title = tk.value || tk.id;
      tr.appendChild(valTd);
      tr.appendChild(el('td', null, tk.location || '-'));
      // status
      var stTd = el('td', 'narrow');
      if (tk.triggers > 0) {
        stTd.appendChild(el('span', 't-crit', 'TRIGGERED'));
      } else {
        stTd.appendChild(el('span', 't-muted', 'quiet'));
      }
      tr.appendChild(stTd);
      tr.appendChild(el('td', 'narrow', tk.triggers));

      // actions
      var actTd = el('td', 'narrow');
      if (tk.type === 'office-doc' || tk.type === 'url' || tk.type === 'web-image') {
        var dlLink = el('a', 'dl-link', '.docx');
        dlLink.href = '/api/tokens/' + encodeURIComponent(tk.id) + '/docx';
        dlLink.target = '_blank'; dlLink.rel = 'noopener';
        actTd.appendChild(dlLink);
      }
      var delBtn = el('button', 'btn-link t-err', 'delete');
      delBtn.addEventListener('click', function () {
        confirmModal('Delete Token', 'Delete token "' + (tk.label || tk.id) + '"? This cannot be undone.').then(function (ok) {
          if (!ok) return;
          api('/api/tokens/' + encodeURIComponent(tk.id), { method: 'DELETE' }).then(function () {
            toast('Token deleted', 'ok');
            viewTokens(c).catch(function (e) { toast(e.message, 'err'); });
          }).catch(function (e) { toast(e.message, 'err'); });
        });
      });
      actTd.appendChild(delBtn);
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });

    tbl.appendChild(tbody);
    panel.appendChild(tbl);
    c.appendChild(panel);
  });
}

// ================================================================
// VIEW: FULL-OS VMS
// ================================================================

function viewVMs(c) {
  return api('/api/vms').then(function (data) {
    c.replaceChildren();

    if (!data.enabled) {
      c.appendChild(emptyState('Full-OS VM decoys are not configured in this deployment.'));
      return;
    }

    var decoys = data.decoys || [];
    if (!decoys.length) {
      c.appendChild(emptyState('No VM decoys provisioned.'));
      return;
    }

    var panel = el('div', 'panel');
    var tbl = el('table', 'tbl');
    var thead = el('thead');
    var hr = el('tr');
    ['Name', 'Persona', 'State', 'Template', 'Baseline', 'Reset', 'Actions'].forEach(function (h) {
      hr.appendChild(el('th', null, h));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);

    var tbody = el('tbody');
    decoys.forEach(function (d) {
      var tr = el('tr');
      tr.appendChild(el('td', null, d.id));
      tr.appendChild(el('td', null, d.persona));

      var stTd = el('td');
      var stCls = d.burned ? 'st-burned' : d.state === 'running' ? 'st-running' : 'st-stopped';
      stTd.appendChild(el('span', stCls, d.burned ? 'BURNED' : d.state));
      tr.appendChild(stTd);

      tr.appendChild(el('td', null, d.template || '-'));
      tr.appendChild(el('td', null, d.baseline ? 'yes' : 'no'));
      tr.appendChild(el('td', null, d.revert || 'never'));

      var actTd = el('td', 'narrow');
      if (!d.burned) {
        // Power control. Reset happens only after a closed engagement, never on
        // a timer — but an operator may need to stop or start a decoy by hand
        // (maintenance, staged rollout). The server refuses a start while the
        // decoy is already running and vice versa.
        var powerAction = d.state === 'running' ? 'stop' : 'start';
        var powerBtn = el('button', 'btn btn-sm btn-secondary',
          powerAction === 'stop' ? 'Stop' : 'Start');
        powerBtn.title = powerAction === 'stop'
          ? 'Power the decoy off. Stops observation and listeners.'
          : 'Power the decoy on.';
        powerBtn.style.marginRight = '4px';
        powerBtn.addEventListener('click', function () {
          toast((powerAction === 'stop' ? 'Stopping ' : 'Starting ') + d.id + '…');
          api('/api/vms/' + encodeURIComponent(d.id) + '/' + powerAction, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'from the operator console' }),
          }).then(function () {
            toast('VM ' + powerAction + ': ' + d.id, 'ok');
            viewVMs(c).catch(function (e) { toast(e.message, 'err'); });
          }).catch(function (e) { toast(e.message, 'err'); });
        });
        actTd.appendChild(powerBtn);

        var burnBtn = el('button', 'btn btn-sm btn-danger', 'Burn');
        burnBtn.title = 'Take out of service and preserve as evidence. Cannot be undone.';
        burnBtn.addEventListener('click', function () {
          confirmModal('Burn VM: ' + d.id,
            'This will permanently take "' + d.id + '" out of service and preserve it as evidence. The VM is never restarted. Continue?'
          ).then(function (ok) {
            if (!ok) return;
            toast('Burning ' + d.id + '…');
            api('/api/vms/' + encodeURIComponent(d.id) + '/burn', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ reason: 'from the operator console' }),
            }).then(function () {
              toast('VM burned: ' + d.id, 'ok');
              viewVMs(c).catch(function (e) { toast(e.message, 'err'); });
            }).catch(function (e) { toast(e.message, 'err'); });
          });
        });
        actTd.appendChild(burnBtn);

        if (data.can_revert) {
          var revertBtn = el('button', 'btn btn-sm btn-secondary', 'Revert');
          revertBtn.title = 'Snapshot dirty state then return to clean baseline.';
          revertBtn.style.marginLeft = '4px';
          revertBtn.addEventListener('click', function () {
            confirmModal('Revert VM: ' + d.id,
              'This will snapshot the current state of "' + d.id + '" and revert to the clean baseline. Continue?'
            ).then(function (ok) {
              if (!ok) return;
              toast('Reverting ' + d.id + '…');
              api('/api/vms/' + encodeURIComponent(d.id) + '/revert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason: 'from the operator console' }),
              }).then(function () {
                toast('VM reverted: ' + d.id, 'ok');
                viewVMs(c).catch(function (e) { toast(e.message, 'err'); });
              }).catch(function (e) { toast(e.message, 'err'); });
            });
          });
          actTd.appendChild(revertBtn);
        }
      } else {
        actTd.appendChild(el('span', 't-muted', d.burn_reason || 'evidence preserved'));
      }
      tr.appendChild(actTd);
      tbody.appendChild(tr);
    });

    tbl.appendChild(tbody);
    panel.appendChild(tbl);
    c.appendChild(panel);
  });
}

// ================================================================
// VIEW: IMAGE LIBRARY
// ================================================================

var DIFFS = ['easy', 'medium', 'hard', 'insane'];

// imageAddPanel builds the two ways to add a decoy image: register a file
// already on the host by path (the catalog's native model), or upload one
// through the browser (guarded server-side: allow-listed extension, base name
// only, size cap, no overwrite).
function imageAddPanel(c) {
  var refresh = function () { viewImages(c).catch(function (e) { toast(e.message, 'err'); }); };
  var panel = el('div', 'panel'); panel.style.marginTop = '16px';
  panel.appendChild(panelHead('Add an image'));
  var body = el('div', 'panel-body padded');

  // --- Register by path ---
  body.appendChild(el('div', 't-sec', 'Register a file already on the host (nothing is copied):'));
  var r1 = el('div', 'form-row'); r1.style.marginTop = '8px';
  var pathInp = el('input', 'f-input'); pathInp.placeholder = '/var/lib/mirage/images/box.qcow2'; pathInp.style.flex = '1';
  var pDiff = el('select', 'f-select');
  DIFFS.forEach(function (d) { pDiff.appendChild(new Option(d, d)); });
  var pPersona = el('input', 'f-input'); pPersona.placeholder = 'persona (optional)'; pPersona.style.maxWidth = '160px';
  var regBtn = el('button', 'btn btn-primary', 'Register');
  regBtn.addEventListener('click', function () {
    if (!pathInp.value.trim()) { toast('Enter a file path', 'err'); return; }
    api('/api/images', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: pathInp.value.trim(), difficulty: pDiff.value, persona: pPersona.value.trim(), checksum: true }),
    }).then(function (im) { toast('Registered ' + (im.id || 'image'), 'ok'); refresh(); })
      .catch(function (e) { toast(e.message, 'err'); });
  });
  r1.appendChild(pathInp); r1.appendChild(pDiff); r1.appendChild(pPersona); r1.appendChild(regBtn);
  body.appendChild(r1);

  // --- Upload ---
  var up = el('div'); up.style.marginTop = '16px';
  up.appendChild(el('div', 't-sec', 'Or upload an image (iso/ova/ovf/qcow2/vmdk/vhd/vhdx/img/raw/vdi). Large images are better placed on disk and registered by path.'));
  var r2 = el('div', 'form-row'); r2.style.marginTop = '8px';
  var fileInp = el('input'); fileInp.type = 'file'; fileInp.className = 'f-input'; fileInp.style.flex = '1';
  var uDiff = el('select', 'f-select');
  DIFFS.forEach(function (d) { uDiff.appendChild(new Option(d, d)); });
  var uPersona = el('input', 'f-input'); uPersona.placeholder = 'persona (optional)'; uPersona.style.maxWidth = '160px';
  var upBtn = el('button', 'btn btn-secondary', 'Upload');
  var prog = el('div', 't-muted'); prog.style.marginTop = '6px';
  upBtn.addEventListener('click', function () {
    if (!fileInp.files || !fileInp.files.length) { toast('Choose a file', 'err'); return; }
    var fd = new FormData();
    fd.append('file', fileInp.files[0]);
    fd.append('difficulty', uDiff.value);
    fd.append('persona', uPersona.value.trim());
    upBtn.disabled = true; prog.textContent = 'Uploading ' + fileInp.files[0].name + '…';
    // FormData sets its own multipart Content-Type; authOpts only adds the token.
    api('/api/images/upload', { method: 'POST', body: fd }).then(function (r) {
      upBtn.disabled = false; prog.textContent = '';
      toast('Uploaded ' + (r.image && r.image.id ? r.image.id : 'image'), 'ok');
      refresh();
    }).catch(function (e) { upBtn.disabled = false; prog.textContent = ''; toast(e.message, 'err'); });
  });
  r2.appendChild(fileInp); r2.appendChild(uDiff); r2.appendChild(uPersona); r2.appendChild(upBtn);
  up.appendChild(r2); up.appendChild(prog);
  body.appendChild(up);

  panel.appendChild(body);
  return panel;
}

function viewImages(c) {
  return tryApi('/api/images').then(function (data) {
    c.replaceChildren();
    var images = (data && data.images) || [];
    var toolOk = data && data.tool_available;

    var intro = el('div', 'panel');
    intro.appendChild(panelHead('Decoy Image Library',
      el('span', 'tag ' + (toolOk ? 'tag-ok' : 'tag-warn'),
         toolOk ? 'virt-customize ready' : 'virt-customize missing')));
    var ib = el('div', 'panel-body padded');
    ib.appendChild(el('div', 't-sec',
      'Import ISO/OVA/OVF/qcow2/vmdk decoy images, tag them by difficulty, and sanitise ' +
      '(strip CTF flags, reset known credentials, embed a watermark) before deploying. ' +
      'Register a file already on the host by path, or upload one below; sanitise/apply ' +
      'run from the CLI (miragectl images).'));
    intro.appendChild(ib);
    c.appendChild(intro);

    c.appendChild(imageAddPanel(c));

    if (!images.length) {
      c.appendChild(emptyState('No images catalogued yet. Register one by path or upload one above.'));
      return;
    }

    var panel = el('div', 'panel');
    panel.style.marginTop = '16px';
    var tbl = el('table', 'tbl');
    var thead = el('thead'); var hr = el('tr');
    ['ID', 'Difficulty', 'Format', 'Persona', 'Source', 'Sanitised', 'Actions'].forEach(function (h) {
      hr.appendChild(el('th', null, h));
    });
    thead.appendChild(hr); tbl.appendChild(thead);
    var tbody = el('tbody');
    images.forEach(function (im) {
      var tr = el('tr');
      tr.appendChild(el('td', null, im.id));

      // Difficulty as an inline selector so an operator can re-tag in place.
      var dTd = el('td', 'narrow');
      var sel = el('select');
      DIFFS.forEach(function (d) {
        var opt = el('option', null, d); opt.value = d;
        if (im.difficulty === d) opt.selected = true;
        sel.appendChild(opt);
      });
      sel.addEventListener('change', function () {
        api('/api/images/' + encodeURIComponent(im.id) + '/retag', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ difficulty: sel.value }),
        }).then(function () { toast('retagged ' + im.id, 'ok'); })
          .catch(function (e) { toast(e.message, 'err'); });
      });
      dTd.appendChild(sel);
      tr.appendChild(dTd);

      tr.appendChild(el('td', 'narrow', im.format));
      tr.appendChild(el('td', null, im.persona || '-'));
      tr.appendChild(el('td', 'narrow', im.source || '-'));

      var sTd = el('td', 'narrow');
      sTd.appendChild(el('span', im.sanitized ? 't-ok' : 't-warn',
        im.sanitized ? 'sanitised' : 'NOT sanitised'));
      tr.appendChild(sTd);

      var aTd = el('td', 'narrow');
      var planBtn = el('button', 'btn btn-sm btn-secondary', 'Sanitise plan');
      planBtn.addEventListener('click', function () { showImagePlan(im.id); });
      aTd.appendChild(planBtn);
      var rmBtn = el('button', 'btn btn-sm btn-danger', 'Remove');
      rmBtn.style.marginLeft = '4px';
      rmBtn.title = 'Forget the catalog entry (the image file is left on disk).';
      rmBtn.addEventListener('click', function () {
        confirmModal('Remove image: ' + im.id,
          'Forget the catalog entry for "' + im.id + '"? The image file on disk is not deleted.'
        ).then(function (ok) {
          if (!ok) return;
          api('/api/images/' + encodeURIComponent(im.id), { method: 'DELETE' }).then(function () {
            toast('removed ' + im.id, 'ok');
            viewImages(c).catch(function (e) { toast(e.message, 'err'); });
          }).catch(function (e) { toast(e.message, 'err'); });
        });
      });
      aTd.appendChild(rmBtn);
      tr.appendChild(aTd);
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    panel.appendChild(tbl);
    c.appendChild(panel);

    // A place for the sanitisation plan to render.
    var planHost = el('div');
    planHost.id = 'image-plan-host';
    planHost.style.marginTop = '16px';
    c.appendChild(planHost);
  });
}

function showImagePlan(id) {
  var host = $('image-plan-host');
  if (!host) return;
  host.replaceChildren(loading());
  tryApi('/api/images/' + encodeURIComponent(id) + '/plan').then(function (data) {
    host.replaceChildren();
    if (!data) { host.appendChild(emptyState('Could not load the plan.')); return; }
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Sanitisation plan: ' + id,
      el('span', 'tag ' + (data.tool_available ? 'tag-ok' : 'tag-warn'),
         data.tool_available ? 'auto-apply ready' : 'CLI apply needed')));
    var body = el('div', 'panel-body padded');
    body.appendChild(el('div', 't-sec', data.note || ''));
    var tbl = el('table', 'tbl');
    tbl.style.marginTop = '10px';
    var thead = el('thead'); var hr = el('tr');
    ['#', 'Action', 'Target'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
    thead.appendChild(hr); tbl.appendChild(thead);
    var tbody = el('tbody');
    (data.actions || []).forEach(function (a, i) {
      var tr = el('tr');
      tr.appendChild(el('td', 'narrow', String(i + 1)));
      tr.appendChild(el('td', 'narrow', a.kind));
      tr.appendChild(el('td', null, a.target));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    body.appendChild(tbl);
    panel.appendChild(body);
    host.appendChild(panel);
  }).catch(function (e) { host.replaceChildren(emptyState(e.message)); });
}

// ================================================================
// VIEW: DETECTION RULES (forge)
// ================================================================

function viewForge(c) {
  c.replaceChildren();

  // Engagement selector
  var header = el('div', 'filters');
  var selLabel = el('span', 't-sec', 'Select engagement: ');
  header.appendChild(selLabel);

  var engSel = el('select', 'f-select');
  engSel.style.minWidth = '220px';
  engSel.appendChild(new Option('-- choose an engagement --', ''));
  header.appendChild(engSel);

  var genBtn = el('button', 'btn btn-primary', 'Generate');
  header.appendChild(genBtn);
  c.appendChild(header);

  var output = el('div');
  c.appendChild(output);

  // Load engagements for selector
  api('/api/engagements?limit=100').then(function (data) {
    (data.engagements || []).forEach(function (e) {
      var label = e.src_ip + ' (risk ' + e.risk_score + ', ' + (e.active ? 'active' : 'closed') + ')';
      var opt = new Option(label, e.id);
      engSel.appendChild(opt);
    });
    if (S.forgeEng) {
      engSel.value = S.forgeEng;
      generateForge(S.forgeEng, output);
    }
  }).catch(function () {});

  genBtn.addEventListener('click', function () {
    var id = engSel.value;
    if (!id) { toast('Select an engagement first', 'err'); return; }
    S.forgeEng = id;
    generateForge(id, output);
  });

  return Promise.resolve();
}

function generateForge(engId, output) {
  output.replaceChildren(loading());
  api('/api/engagements/' + encodeURIComponent(engId) + '/forge').then(function (bundle) {
    output.replaceChildren();
    var rules = bundle.rules || [];
    var iocs = bundle.iocs || [];

    // Summary and download links
    var summary = el('div', 'filters');
    summary.appendChild(el('span', 't-sec',
      rules.length + ' rule(s) and ' + iocs.length + ' indicator(s)'));
    var dlBase = '/api/engagements/' + encodeURIComponent(engId) + '/forge?format=';
    ['sigma', 'suricata', 'yara', 'stix', 'report'].forEach(function (fmt) {
      var a = el('a', 'dl-link', fmt);
      a.href = dlBase + fmt;
      a.target = '_blank'; a.rel = 'noopener';
      summary.appendChild(a);
    });
    output.appendChild(summary);

    // Rules
    if (!rules.length) {
      output.appendChild(emptyState('Nothing in this engagement was specific enough to signature.'));
    } else {
      var panel = el('div', 'panel');
      rules.forEach(function (r) {
        var block = el('div', 'rule-block');
        var title = el('div', 'rule-title');
        title.appendChild(document.createTextNode(r.title + ' '));
        title.appendChild(el('span', 'tag', r.format));
        if (r.technique) title.appendChild(el('span', 'tag tag-att', r.technique));
        block.appendChild(title);
        block.appendChild(el('div', 'rule-rationale', r.rationale));
        block.appendChild(highlightRule(r.content, r.format));

        var actions = el('div', 'rule-actions');
        var copyBtn = el('button', 'btn btn-sm btn-ghost', 'Copy');
        copyBtn.addEventListener('click', function () { copyText(r.content); });
        actions.appendChild(copyBtn);
        block.appendChild(actions);
        panel.appendChild(block);
      });
      output.appendChild(panel);
    }

    // IOCs
    if (iocs.length) {
      var iocPanel = el('div', 'panel');
      iocPanel.style.marginTop = '16px';
      var iocHead = panelHead('Indicators of Compromise (' + iocs.length + ')');
      var copyAll = el('button', 'btn btn-sm btn-ghost', 'Copy All');
      copyAll.addEventListener('click', function () {
        copyText(iocs.map(function (i) { return (i.type || '') + '\t' + (i.value || i); }).join('\n'));
      });
      iocHead.appendChild(copyAll);
      iocPanel.appendChild(iocHead);
      var iocBody = el('div', 'panel-body');
      var iocTbl = el('table', 'tbl');
      var iocThead = el('thead');
      var iocHr = el('tr');
      iocHr.appendChild(el('th', null, 'Type'));
      iocHr.appendChild(el('th', null, 'Value'));
      iocThead.appendChild(iocHr);
      iocTbl.appendChild(iocThead);
      var iocTbody = el('tbody');
      iocs.forEach(function (ioc) {
        var tr = el('tr');
        tr.appendChild(el('td', 'narrow', ioc.type || 'indicator'));
        var valTd = el('td');
        valTd.textContent = ioc.value || String(ioc);
        tr.appendChild(valTd);
        iocTbody.appendChild(tr);
      });
      iocTbl.appendChild(iocTbody);
      iocBody.appendChild(iocTbl);
      iocPanel.appendChild(iocBody);
      output.appendChild(iocPanel);
    }

    // Rejected candidates
    if ((bundle.rejected || []).length) {
      var rejDiv = el('div', 'rejected-block');
      rejDiv.style.marginTop = '16px';
      rejDiv.appendChild(el('b', null, 'Deliberately not turned into rules. '));
      rejDiv.appendChild(document.createTextNode('A rule that fires on normal activity gets the whole feed switched off.'));
      bundle.rejected.forEach(function (rj) {
        var line = el('div');
        line.style.marginTop = '4px';
        line.textContent = rj.candidate + ' — ' + rj.reason;
        rejDiv.appendChild(line);
      });
      output.appendChild(rejDiv);
    }
  }).catch(function (e) {
    output.replaceChildren(el('div', 'empty-state', 'Failed: ' + e.message));
  });
}

// ================================================================
// VIEW: EVIDENCE CHAIN
// ================================================================

function viewEvidence(c) {
  return api('/api/stats').then(function (stats) {
    c.replaceChildren();

    // Chain info
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Evidence Chain'));
    var body = el('div', 'panel-body padded');
    var t = el('table', 'kv');
    kvRow(t, 'events stored', stats.storage.events);
    kvRow(t, 'head sequence', '#' + stats.storage.head_seq);
    kvRow(t, 'head hash', stats.storage.head_hash || '-');
    body.appendChild(t);
    panel.appendChild(body);
    c.appendChild(panel);

    // Verification
    var verifyPanel = el('div', 'panel');
    verifyPanel.style.marginTop = '16px';
    verifyPanel.appendChild(panelHead('Integrity Verification'));
    var vBody = el('div', 'panel-body padded');
    var desc = el('div', 't-sec');
    desc.style.marginBottom = '12px';
    desc.textContent = 'Replay the append-only hash chain to verify no event has been tampered with, deleted, or reordered. This operation reads every event in the store.';
    vBody.appendChild(desc);

    var resultDiv = el('div');
    resultDiv.style.marginTop = '12px';
    vBody.appendChild(resultDiv);

    var verifyBtn = el('button', 'btn btn-primary', 'Verify Evidence Chain');
    verifyBtn.addEventListener('click', function () {
      verifyBtn.disabled = true;
      verifyBtn.textContent = 'Verifying…';
      resultDiv.replaceChildren(loading());
      api('/api/evidence/verify', { method: 'POST' }).then(function (r) {
        verifyBtn.disabled = false;
        verifyBtn.textContent = 'Verify Evidence Chain';
        resultDiv.replaceChildren();
        var rt = el('table', 'kv');
        if (r.verified) {
          var ok = el('div', 't-ok');
          ok.style.fontSize = '14px'; ok.style.fontWeight = '700'; ok.style.marginBottom = '8px';
          ok.textContent = 'VERIFIED: Evidence chain is intact.';
          resultDiv.appendChild(ok);
          kvRow(rt, 'events verified', r.events);
          kvRow(rt, 'head sequence', '#' + r.head_seq);
          kvRow(rt, 'head hash', r.head_hash);
          kvRow(rt, 'duration', r.took);
        } else {
          var bad = el('div', 't-err');
          bad.style.fontSize = '14px'; bad.style.fontWeight = '700'; bad.style.marginBottom = '8px';
          bad.textContent = 'TAMPERED: Evidence chain verification failed.';
          resultDiv.appendChild(bad);
          kvRow(rt, 'error', r.error);
          kvRow(rt, 'events', r.events);
          kvRow(rt, 'duration', r.took);
        }
        resultDiv.appendChild(rt);
      }).catch(function (e) {
        verifyBtn.disabled = false;
        verifyBtn.textContent = 'Verify Evidence Chain';
        resultDiv.replaceChildren(el('div', 't-err', 'Error: ' + e.message));
      });
    });
    vBody.appendChild(verifyBtn);
    verifyPanel.appendChild(vBody);
    c.appendChild(verifyPanel);
  });
}

// ================================================================
// VIEW: COMPLIANCE
// ================================================================

var FRAMEWORKS = [
  { id: 'nis2',     label: 'NIS2' },
  { id: 'dora',     label: 'DORA' },
  { id: 'iso27001', label: 'ISO 27001' },
  { id: 'pci',      label: 'PCI DSS' },
  { id: 'soc2',     label: 'SOC 2' },
  { id: 'iec62443', label: 'IEC 62443' },
];

function viewCompliance(c) {
  c.replaceChildren();

  // Framework selector
  var pills = el('div', 'pills');
  FRAMEWORKS.forEach(function (fw) {
    var pill = el('button', 'pill' + (S.compFw === fw.id ? ' active' : ''), fw.label);
    pill.addEventListener('click', function () {
      S.compFw = fw.id;
      viewCompliance(c).catch(function (e) { toast(e.message, 'err'); });
    });
    pills.appendChild(pill);
  });
  c.appendChild(pills);

  var output = el('div');
  output.appendChild(loading());
  c.appendChild(output);

  // The server exposes the framework as a path segment, not a query parameter.
  return tryApi('/api/compliance/' + encodeURIComponent(S.compFw)).then(function (data) {
    output.replaceChildren();
    if (!data) {
      // Endpoint genuinely unreachable (older deployment) — degrade gracefully.
      var panel = el('div', 'panel');
      panel.appendChild(panelHead('Compliance: ' + S.compFw.toUpperCase()));
      var body = el('div', 'panel-body padded');
      body.appendChild(el('div', 't-sec',
        'The compliance reporting endpoint is not reachable in this deployment. ' +
        'Use miragectl compliance to generate a report from the command line.'));
      panel.appendChild(body);
      output.appendChild(panel);
      return;
    }

    // Render compliance data from API. The server returns:
    //   { framework, controls[{id,title,description,satisfied,evidence}],
    //     passed, total, coverage }  where coverage is a 0..100 percentage.
    var panel = el('div', 'panel');
    var countBadge = data.total != null
      ? el('span', 'tag tag-accent', data.passed + '/' + data.total)
      : null;
    panel.appendChild(panelHead('Compliance: ' + (data.framework || S.compFw.toUpperCase()), countBadge));
    var body = el('div', 'panel-body padded');

    if (data.coverage != null) {
      var pct = Math.round(data.coverage);
      body.appendChild(el('div', 't-accent', pct + '% coverage'));
      var track = el('div', 'progress-track');
      track.style.marginTop = '8px'; track.style.marginBottom = '16px';
      var fill = el('div', 'progress-fill');
      fill.style.width = pct + '%';
      fill.style.background = pct > 70 ? 'var(--ok)' : pct > 40 ? 'var(--warn)' : 'var(--err)';
      track.appendChild(fill);
      body.appendChild(track);
    }

    if (data.controls && data.controls.length) {
      var tbl = el('table', 'tbl');
      var thead = el('thead');
      var hr = el('tr');
      ['Control', 'Title', 'Status', 'Evidence'].forEach(function (h) {
        hr.appendChild(el('th', null, h));
      });
      thead.appendChild(hr);
      tbl.appendChild(thead);
      var tbody = el('tbody');
      data.controls.forEach(function (ctrl) {
        var tr = el('tr');
        tr.appendChild(el('td', 'narrow', ctrl.id || ''));
        tr.appendChild(el('td', null, ctrl.title || ctrl.description || ''));
        var stTd = el('td', 'narrow');
        stTd.appendChild(el('span', ctrl.satisfied ? 't-ok' : 't-muted', ctrl.satisfied ? 'satisfied' : 'gap'));
        tr.appendChild(stTd);
        tr.appendChild(el('td', null, ctrl.evidence || ''));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      body.appendChild(tbl);
    } else {
      body.appendChild(el('div', 't-muted', 'No controls returned for this framework.'));
    }

    panel.appendChild(body);
    output.appendChild(panel);
  });
}

// ================================================================
// VIEW: OBSERVER / VMI
// ================================================================

function viewObserver(c) {
  return tryApi('/api/observer').then(function (data) {
    c.replaceChildren();
    c.appendChild(el('h2', null, 'Observer / VMI'));

    if (!data || !data.configured) {
      var msg = el('div', 'empty-state');
      msg.appendChild(el('div', 'empty-icon', '◈'));
      msg.appendChild(el('div', null, 'No observer driver configured.'));
      msg.appendChild(el('p', null,
        'The observer watches inside full-OS VM decoys from the hypervisor — ' +
        'process, file, registry and injection activity, reconstructed without ' +
        'anything inside the guest for the attacker to find or disable.'));
      var hint = el('div', 'help-block');
      hint.appendChild(el('strong', null, 'To enable:'));
      hint.appendChild(el('span', null, ' set drivers.observer: drakvuf in your profile and deploy on a Xen dom0 host.'));
      msg.appendChild(hint);
      c.appendChild(msg);
      return;
    }

    // Status card
    var grid = el('div', 'section-grid');
    grid.appendChild(statCard('Driver', data.driver));
    grid.appendChild(statCard('Status', data.probe_error ? 'Unavailable' : 'Ready'));
    grid.appendChild(statCard('Experimental', data.experimental ? 'Yes' : 'No'));
    c.appendChild(grid);

    // Capabilities
    if (data.capabilities && data.capabilities.length) {
      c.appendChild(el('h3', null, 'Capabilities'));
      var capGrid = el('div', 'section-grid');
      data.capabilities.forEach(function (cap) {
        var name = cap.replace('observer.', '');
        capGrid.appendChild(statCard(name, '✓'));
      });
      c.appendChild(capGrid);
    }

    // Summary
    if (data.summary) {
      c.appendChild(el('h3', null, 'Summary'));
      c.appendChild(el('p', null, data.summary));
    }

    // Probe error
    if (data.probe_error) {
      c.appendChild(el('h3', null, 'Probe Error'));
      var errBox = el('pre', 'code-block');
      errBox.textContent = data.probe_error;
      c.appendChild(errBox);
    }

    // VM dump section
    c.appendChild(el('h3', null, 'Memory Dump'));
    c.appendChild(el('p', null,
      'Trigger a full memory dump of a running VM decoy for forensic analysis.'));
    var form = el('div', 'form-row');
    var inp = el('input');
    inp.type = 'text';
    inp.placeholder = 'VM decoy ID (e.g. vm-dc01)';
    inp.style.cssText = 'flex:1;padding:8px;border:1px solid var(--border);border-radius:4px;background:var(--bg-card);color:var(--fg)';
    form.appendChild(inp);
    var dumpBtn = el('button', 'btn btn-warn', 'Dump Memory');
    dumpBtn.addEventListener('click', function () {
      var id = inp.value.trim();
      if (!id) { toast('Enter a decoy ID', 'err'); return; }
      dumpBtn.disabled = true;
      dumpBtn.textContent = 'Dumping...';
      api('/api/observer/' + encodeURIComponent(id) + '/dump', { method: 'POST' })
        .then(function (res) {
          toast('Memory dump saved: ' + res.path, 'ok');
          dumpBtn.disabled = false;
          dumpBtn.textContent = 'Dump Memory';
        })
        .catch(function (e) {
          toast('Dump failed: ' + e.message, 'err');
          dumpBtn.disabled = false;
          dumpBtn.textContent = 'Dump Memory';
        });
    });
    form.appendChild(dumpBtn);
    c.appendChild(form);
  });
}

// VIEW: RANSOMWARE TRAP
// ================================================================

function viewTrap(c) {
  return tryApi('/api/trap').then(function (data) {
    c.replaceChildren();

    if (!data || !data.enabled) {
      var panel0 = el('div', 'panel');
      panel0.appendChild(panelHead('Ransomware Trap'));
      var b0 = el('div', 'panel-body padded');
      b0.appendChild(el('div', 't-sec',
        (data && data.message) ||
        'No ransomware trap is configured in this deployment. The ransomware detector ' +
        'still runs inside the emulated FTP/SMB services; the trap adds a hypervisor-agnostic ' +
        'FUSE share that works on KVM/Proxmox, VMware and Hyper-V without VMI.'));
      panel0.appendChild(b0);
      c.appendChild(panel0);
      return;
    }

    var v = data.verdict || {};
    var m = data.metrics || {};

    // Verdict banner.
    var panel = el('div', 'panel');
    var badge = v.Confirmed
      ? el('span', 'tag tag-err', 'RANSOMWARE CONFIRMED')
      : v.Score > 0 ? el('span', 'tag tag-warn', 'suspicious')
      : el('span', 'tag tag-ok', 'quiet');
    panel.appendChild(panelHead('Ransomware Trap', badge));
    var body = el('div', 'panel-body padded');

    // Suspicion meter.
    var score = v.Score || 0;
    body.appendChild(el('div', 't-accent', 'suspicion score: ' + score));
    var track = el('div', 'progress-track');
    track.style.marginTop = '8px'; track.style.marginBottom = '16px';
    var fill = el('div', 'progress-fill');
    var pct = Math.min(100, score);
    fill.style.width = pct + '%';
    fill.style.background = v.Confirmed ? 'var(--err)' : score > 40 ? 'var(--warn)' : 'var(--ok)';
    track.appendChild(fill);
    body.appendChild(track);

    // Impact metrics — the numbers that make the defence measurable.
    var t = el('table', 'kv');
    kvRow(t, 'files touched', v.FilesTouched != null ? v.FilesTouched : 0);
    kvRow(t, 'operations seen', m.ops_seen != null ? m.ops_seen : 0);
    kvRow(t, 'writes seen', m.writes_seen != null ? m.writes_seen : 0);
    kvRow(t, 'canary hits', m.canary_hits != null ? m.canary_hits : 0);
    if (m.first_signal_ops) kvRow(t, 'first signal at op', m.first_signal_ops);
    if (m.confirm_ops) kvRow(t, 'confirmed at op', m.confirm_ops);
    if (m.tarpit_total) kvRow(t, 'tarpit time imposed', fmtDuration(m.tarpit_total));
    if ((v.Extensions || []).length) kvRow(t, 'new extensions', v.Extensions.join(', '));
    if (v.Note) kvRow(t, 'ransom note', v.Note);
    body.appendChild(t);
    panel.appendChild(body);
    c.appendChild(panel);

    // The bait share contents.
    var listing = data.listing || [];
    if (listing.length) {
      var lp = el('div', 'panel');
      lp.style.marginTop = '16px';
      lp.appendChild(panelHead('Trap Share (top level)'));
      var lb = el('div', 'panel-body padded');
      var tbl = el('table', 'tbl');
      var thead = el('thead'); var hr = el('tr');
      ['Name', 'Type', 'Size', 'Canary'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
      thead.appendChild(hr); tbl.appendChild(thead);
      var tbody = el('tbody');
      listing.forEach(function (e) {
        var tr = el('tr');
        tr.appendChild(el('td', null, e.Name));
        tr.appendChild(el('td', 'narrow', e.Dir ? 'dir' : 'file'));
        tr.appendChild(el('td', 'narrow', e.Dir ? '-' : String(e.Size)));
        var cTd = el('td', 'narrow');
        if (e.Canary) cTd.appendChild(el('span', 't-warn', 'canary'));
        tr.appendChild(cTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      lb.appendChild(tbl);
      lp.appendChild(lb);
      c.appendChild(lp);
    }
  });
}

// fmtDuration renders a Go nanosecond duration (as JSON number) as a short
// human string.
function fmtDuration(ns) {
  if (ns == null) return '';
  var s = ns / 1e9;
  if (s < 1) return Math.round(ns / 1e6) + 'ms';
  if (s < 60) return s.toFixed(1) + 's';
  var m = Math.floor(s / 60);
  return m + 'm ' + Math.round(s - m * 60) + 's';
}

// VIEW: TOPOLOGY (deception estate map)
// ================================================================

var SVG_NS = 'http://www.w3.org/2000/svg';

function svgEl(tag, attrs) {
  var n = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    Object.keys(attrs).forEach(function (k) { n.setAttribute(k, String(attrs[k])); });
  }
  return n;
}

// Colour per node type. Kept in sync with the server's node "type" values
// (director, decoy, vm, hub, agent).
var TOPO_COLORS = {
  director: 'var(--accent)',
  decoy:    'var(--ok)',
  vm:       'var(--purple)',
  hub:      'var(--warn)',
  agent:    'var(--text-muted)',
};

function viewTopology(c) {
  return api('/api/topology').then(function (data) {
    c.replaceChildren();

    var nodes = data.nodes || [];
    var edges = data.edges || [];

    if (!nodes.length) {
      c.appendChild(emptyState('No topology to display — no decoys, VMs or overlay agents are bound yet.'));
      return;
    }

    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Deception Estate',
      el('span', 'tag tag-accent', data.count_nodes + ' nodes · ' + data.count_edges + ' links')));
    var body = el('div', 'panel-body padded');

    // Deterministic radial layout: the director sits in the centre, every
    // other node is placed on a ring around it. No physics, no external graph
    // library (CSP forbids remote scripts) — just trig, so the picture is
    // stable between refreshes and an analyst can memorise where things are.
    var W = 720, H = 520, cx = W / 2, cy = H / 2;
    var center = null;
    var ring = [];
    nodes.forEach(function (n) {
      if (n.type === 'director') center = n; else ring.push(n);
    });
    if (!center) { center = ring.shift(); }

    var pos = {};
    if (center) pos[center.id] = { x: cx, y: cy };
    var R = Math.min(W, H) / 2 - 70;
    ring.forEach(function (n, i) {
      var ang = (2 * Math.PI * i) / Math.max(ring.length, 1) - Math.PI / 2;
      pos[n.id] = { x: cx + R * Math.cos(ang), y: cy + R * Math.sin(ang) };
    });

    var svg = svgEl('svg', {
      viewBox: '0 0 ' + W + ' ' + H, width: '100%',
      preserveAspectRatio: 'xMidYMid meet',
    });
    svg.style.maxWidth = W + 'px';
    svg.style.display = 'block';
    svg.style.margin = '0 auto';

    // Edges first, so nodes draw on top.
    edges.forEach(function (e) {
      var a = pos[e.from], b = pos[e.to];
      if (!a || !b) return;
      var line = svgEl('line', {
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
        stroke: 'var(--border)', 'stroke-width': 1.5,
      });
      svg.appendChild(line);
      if (e.label) {
        var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        var lbl = svgEl('text', {
          x: mx, y: my - 3, 'text-anchor': 'middle',
          'font-size': 10, fill: 'var(--text-muted)',
        });
        lbl.textContent = e.label;
        svg.appendChild(lbl);
      }
    });

    // Nodes.
    nodes.forEach(function (n) {
      var p = pos[n.id];
      if (!p) return;
      var g = svgEl('g', null);
      var isCenter = (center && n.id === center.id);
      var r = isCenter ? 16 : 11;
      var circle = svgEl('circle', {
        cx: p.x, cy: p.y, r: r,
        fill: TOPO_COLORS[n.type] || 'var(--text-muted)',
        stroke: 'var(--bg)', 'stroke-width': 2,
      });
      var title = svgEl('title', null);
      title.textContent = n.type + ': ' + (n.label || n.id) + (n.ip ? ' (' + n.ip + ')' : '');
      circle.appendChild(title);
      g.appendChild(circle);

      var caption = svgEl('text', {
        x: p.x, y: p.y + r + 13, 'text-anchor': 'middle',
        'font-size': 11, fill: 'var(--text)',
      });
      caption.textContent = n.label || n.id;
      g.appendChild(caption);

      if (n.ip) {
        var ipt = svgEl('text', {
          x: p.x, y: p.y + r + 25, 'text-anchor': 'middle',
          'font-size': 9, fill: 'var(--text-muted)',
        });
        ipt.textContent = n.ip;
        g.appendChild(ipt);
      }
      svg.appendChild(g);
    });

    body.appendChild(svg);

    // Legend.
    var legend = el('div', 'topo-legend');
    legend.style.marginTop = '12px';
    legend.style.display = 'flex';
    legend.style.flexWrap = 'wrap';
    legend.style.gap = '14px';
    [['director', 'Director'], ['decoy', 'Decoy service'], ['vm', 'Full-OS VM'],
     ['hub', 'Presence hub'], ['agent', 'Overlay agent']].forEach(function (pair) {
      var item = el('span');
      item.style.display = 'inline-flex';
      item.style.alignItems = 'center';
      item.style.gap = '6px';
      var dot = el('span');
      dot.style.width = '10px'; dot.style.height = '10px';
      dot.style.borderRadius = '50%';
      dot.style.background = TOPO_COLORS[pair[0]];
      dot.style.display = 'inline-block';
      item.appendChild(dot);
      item.appendChild(el('span', 't-muted', pair[1]));
      legend.appendChild(item);
    });
    body.appendChild(legend);

    panel.appendChild(body);
    c.appendChild(panel);
  });
}

// VIEW: PRESENCE (overlay)
// ================================================================

function viewPresence(c) {
  return api('/api/presence').then(function (data) {
    c.replaceChildren();

    if (!data.enabled) {
      c.appendChild(emptyState('Overlay presence is not configured in this deployment.'));
      return;
    }

    // Hub status
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Overlay Hub'));
    var body = el('div', 'panel-body padded');
    var ht = el('table', 'kv');
    kvRow(ht, 'status', 'active');
    kvRow(ht, 'hub address', data.hub);
    kvRow(ht, 'connected agents', data.connected || (data.agents || []).length);
    body.appendChild(ht);
    panel.appendChild(body);
    c.appendChild(panel);

    // Agents list
    var agents = data.agents || [];
    var agentPanel = el('div', 'panel');
    agentPanel.style.marginTop = '16px';
    agentPanel.appendChild(panelHead('Connected Agents (' + agents.length + ')'));
    var aBody = el('div', 'panel-body');

    if (!agents.length) {
      aBody.appendChild(emptyStateSm('No agents connected. The hub is listening at ' + (data.hub || '?') + '.'));
    } else {
      var tbl = el('table', 'tbl');
      var thead = el('thead');
      var hr = el('tr');
      ['Agent ID', 'Persona', 'Decoy', 'Remote Address', 'Services'].forEach(function (h) {
        hr.appendChild(el('th', null, h));
      });
      thead.appendChild(hr);
      tbl.appendChild(thead);
      var tbody = el('tbody');
      agents.forEach(function (a) {
        var tr = el('tr');
        tr.appendChild(el('td', null, a.id));
        tr.appendChild(el('td', null, a.persona || '-'));
        tr.appendChild(el('td', null, a.decoy_id || '-'));
        tr.appendChild(el('td', null, a.remote || '-'));
        var sTd = el('td');
        tagList(sTd, a.services);
        tr.appendChild(sTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      aBody.appendChild(tbl);
    }

    agentPanel.appendChild(aBody);
    c.appendChild(agentPanel);
  });
}

// ================================================================
// VIEW: CONFIGURATION
// ================================================================

function viewConfig(c) {
  return api('/api/config').then(function (cfg) {
    c.replaceChildren();

    // Current config
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Running Configuration'));
    var body = el('div', 'panel-body padded');
    var pre = el('div', 'config-block');
    pre.textContent = JSON.stringify(cfg, null, 2);
    body.appendChild(pre);
    panel.appendChild(body);
    c.appendChild(panel);

    // Listeners
    if (cfg.bound && cfg.bound.length) {
      var lPanel = el('div', 'panel');
      lPanel.style.marginTop = '16px';
      lPanel.appendChild(panelHead('Bound Listeners (' + cfg.bound.length + ')'));
      var lBody = el('div', 'panel-body');
      var tbl = el('table', 'tbl');
      var thead = el('thead');
      var hr = el('tr');
      ['Decoy', 'Persona', 'Service', 'Address', 'Protocol'].forEach(function (h) {
        hr.appendChild(el('th', null, h));
      });
      thead.appendChild(hr);
      tbl.appendChild(thead);
      var tbody = el('tbody');
      cfg.bound.forEach(function (l) {
        var tr = el('tr');
        tr.appendChild(el('td', null, l.decoy_id));
        tr.appendChild(el('td', null, l.persona));
        tr.appendChild(el('td', null, l.service));
        tr.appendChild(el('td', null, l.address));
        tr.appendChild(el('td', null, l.proto));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      lBody.appendChild(tbl);
      lPanel.appendChild(lBody);
      c.appendChild(lPanel);
    }

    // Plan / Apply
    var applyPanel = el('div', 'panel');
    applyPanel.style.marginTop = '16px';
    applyPanel.appendChild(panelHead('Apply Configuration'));
    var aBody = el('div', 'panel-body padded');
    aBody.appendChild(el('div', 't-sec',
      'Paste a YAML manifest below and click Plan to see the diff, or Apply to reconcile the running deployment.'));

    var ta = el('textarea', 'f-input');
    ta.style.width = '100%'; ta.style.minHeight = '180px';
    ta.style.marginTop = '12px'; ta.style.fontFamily = 'var(--mono)';
    ta.style.fontSize = '12px'; ta.style.resize = 'vertical';
    ta.style.background = 'var(--bg-input)'; ta.style.color = 'var(--text)';
    ta.style.border = '1px solid var(--border)'; ta.style.borderRadius = 'var(--radius-s)';
    ta.style.padding = '10px';
    ta.placeholder = '# Paste your YAML manifest here...';
    aBody.appendChild(ta);

    var btnRow = el('div', 'form-row');
    btnRow.style.marginTop = '12px';

    var planBtn = el('button', 'btn btn-secondary', 'Plan (dry run)');
    var applyBtn = el('button', 'btn btn-danger', 'Apply');

    var resultDiv = el('div');
    resultDiv.style.marginTop = '12px';

    function doAction(action) {
      var yaml = ta.value.trim();
      if (!yaml) { toast('Paste a YAML manifest first', 'err'); return; }
      resultDiv.replaceChildren(loading());
      api('/api/config/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-yaml' },
        body: yaml,
      }).then(function (r) {
        resultDiv.replaceChildren();
        var rt = el('table', 'kv');
        kvRow(rt, 'action', action);
        kvRow(rt, 'applied', r.applied ? 'yes' : 'no (dry run)');
        kvRow(rt, 'summary', r.summary);
        if (r.added) kvRow(rt, 'added', r.added.join(', '));
        if (r.removed) kvRow(rt, 'removed', r.removed.join(', '));
        if (r.error) kvRow(rt, 'error', r.error);
        resultDiv.appendChild(rt);
        if (r.plan) {
          resultDiv.appendChild(el('pre', null, JSON.stringify(r.plan, null, 2)));
        }
        toast(action + ': ' + (r.summary || (r.applied ? 'applied' : 'planned')), r.error ? 'err' : 'ok');
      }).catch(function (e) {
        resultDiv.replaceChildren(el('div', 't-err', 'Error: ' + e.message));
        toast(e.message, 'err');
      });
    }

    planBtn.addEventListener('click', function () { doAction('plan'); });
    applyBtn.addEventListener('click', function () {
      confirmModal('Apply Configuration',
        'This will reconcile the running deployment with the manifest. Listeners may be added or removed. Continue?'
      ).then(function (ok) {
        if (ok) doAction('apply');
      });
    });

    btnRow.appendChild(planBtn);
    btnRow.appendChild(applyBtn);
    aBody.appendChild(btnRow);
    aBody.appendChild(resultDiv);
    applyPanel.appendChild(aBody);
    c.appendChild(applyPanel);
  });
}

// ================================================================
// VIEW: ABOUT / STATUS
// ================================================================

function viewAbout(c) {
  return Promise.all([
    api('/api/health'),
    api('/api/stats'),
    api('/api/drivers'),
    tryApi('/api/economics'),
  ]).then(function (results) {
    var health = results[0], stats = results[1], drivers = results[2], econ = results[3];
    c.replaceChildren();

    // Product info
    var infoPanel = el('div', 'panel');
    infoPanel.appendChild(panelHead('Product'));
    var infoBody = el('div', 'panel-body padded');
    var it = el('table', 'kv');
    kvRow(it, 'product', health.product);
    kvRow(it, 'version', health.version);
    kvRow(it, 'status', health.status);
    kvRow(it, 'uptime', health.uptime);
    kvRow(it, 'tenant', stats.tenant);
    kvRow(it, 'site', stats.site);
    infoBody.appendChild(it);
    infoPanel.appendChild(infoBody);
    c.appendChild(infoPanel);

    var grid = el('div', 'section-grid');

    // Driver registry
    var drvPanel = el('div', 'panel');
    drvPanel.appendChild(panelHead('Driver Registry'));
    var drvBody = el('div', 'panel-body');
    var drvList = drivers.drivers || [];
    if (!drvList.length) {
      drvBody.appendChild(emptyStateSm('No drivers registered.'));
    } else {
      var tbl = el('table', 'tbl');
      var thead = el('thead');
      var hr = el('tr');
      ['Category', 'Name', 'Capabilities'].forEach(function (h) {
        hr.appendChild(el('th', null, h));
      });
      thead.appendChild(hr);
      tbl.appendChild(thead);
      var tbody = el('tbody');
      drvList.forEach(function (d) {
        var tr = el('tr');
        tr.appendChild(el('td', null, d.category || d.Category || '-'));
        tr.appendChild(el('td', null, d.name || d.Name || '-'));
        var capTd = el('td');
        var caps = d.capabilities || d.Capabilities || d.caps || [];
        if (typeof caps === 'string') caps = [caps];
        tagList(capTd, caps);
        tr.appendChild(capTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      drvBody.appendChild(tbl);
    }
    drvPanel.appendChild(drvBody);
    grid.appendChild(drvPanel);

    // Economics
    var econPanel = el('div', 'panel');
    econPanel.appendChild(panelHead('Engagement Economics'));
    var econBody = el('div', 'panel-body padded');
    if (econ) {
      var et = el('table', 'kv');
      Object.entries(econ).forEach(function (pair) {
        kvRow(et, pair[0].replace(/_/g, ' '), typeof pair[1] === 'object' ? JSON.stringify(pair[1]) : pair[1]);
      });
      econBody.appendChild(et);
    } else {
      econBody.appendChild(el('div', 't-muted', 'Economics data not available.'));
    }
    econPanel.appendChild(econBody);
    grid.appendChild(econPanel);

    c.appendChild(grid);

    // Actions
    var actPanel = el('div', 'panel');
    actPanel.style.marginTop = '16px';
    actPanel.appendChild(panelHead('Diagnostics'));
    var actBody = el('div', 'panel-body padded');
    var actRow = el('div', 'form-row');

    // Self-test
    var testBtn = el('button', 'btn btn-secondary', 'Run Self-Test');
    testBtn.title = 'Attack the decoys with harmless probes and check that each one was recorded.';
    var testResult = el('div');
    testResult.style.marginTop = '12px';

    testBtn.addEventListener('click', function () {
      testBtn.disabled = true;
      testBtn.textContent = 'Testing…';
      testResult.replaceChildren(loading());
      api('/api/assure', { method: 'POST' }).then(function (r) {
        testBtn.disabled = false;
        testBtn.textContent = 'Run Self-Test';
        testResult.replaceChildren();
        var status = el('div', r.healthy ? 't-ok' : 't-err');
        status.style.fontWeight = '700';
        status.textContent = r.summary;
        testResult.appendChild(status);
        toast(r.summary, r.healthy ? 'ok' : 'err');
      }).catch(function (e) {
        testBtn.disabled = false;
        testBtn.textContent = 'Run Self-Test';
        testResult.replaceChildren(el('div', 't-err', e.message));
      });
    });
    actRow.appendChild(testBtn);

    // Fingerprint
    var fpBtn = el('button', 'btn btn-secondary', 'Detectability Score');
    fpBtn.title = 'Score how identifiable each decoy is to an attacker.';
    fpBtn.addEventListener('click', function () {
      fpBtn.disabled = true;
      fpBtn.textContent = 'Scoring…';
      testResult.replaceChildren(loading());
      api('/api/assure/fingerprint', { method: 'POST' }).then(function (r) {
        fpBtn.disabled = false;
        fpBtn.textContent = 'Detectability Score';
        testResult.replaceChildren();
        if (r.score != null) {
          var scDiv = el('div');
          scDiv.style.marginBottom = '8px';
          var scLabel = el('span', 't-sec', 'Overall detectability: ');
          var scVal = el('span');
          scVal.style.fontSize = '18px'; scVal.style.fontWeight = '700';
          scVal.className = r.score < 30 ? 't-ok' : r.score < 60 ? 't-warn' : 't-err';
          scVal.textContent = r.score + '/100';
          scDiv.appendChild(scLabel);
          scDiv.appendChild(scVal);
          testResult.appendChild(scDiv);
        }
        if (r.decoys) {
          r.decoys.forEach(function (d) {
            var rt = el('table', 'kv');
            rt.style.marginTop = '8px';
            kvRow(rt, 'decoy', d.decoy_id || d.DecoyID);
            kvRow(rt, 'score', d.score || d.Score);
            if (d.findings) {
              d.findings.forEach(function (f) {
                kvRow(rt, f.check || 'finding', f.detail || f.message);
              });
            }
            testResult.appendChild(rt);
          });
        }
        testResult.appendChild(el('pre', null, JSON.stringify(r, null, 2)));
      }).catch(function (e) {
        fpBtn.disabled = false;
        fpBtn.textContent = 'Detectability Score';
        testResult.replaceChildren(el('div', 't-err', e.message));
      });
    });
    actRow.appendChild(fpBtn);

    actBody.appendChild(actRow);
    actBody.appendChild(testResult);
    actPanel.appendChild(actBody);
    c.appendChild(actPanel);
  });
}

// ================================================================
// KEYBOARD
// ================================================================

document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') closeDrawer();
});

// ================================================================
// VIEW: DECEPTION PACKS
// ================================================================

function viewPacks(c) {
  return api('/api/packs').then(function (data) {
    c.replaceChildren();
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Deception Packs',
      el('span', 'tag tag-accent', (data.packs || []).length + ' packs')));
    var body = el('div', 'panel-body');
    body.appendChild(el('div', 't-sec padded',
      'Signed, versioned bundles of deception content (personas, decoys, honeytokens). ' +
      'Apply from the CLI: miragectl packs apply <name>.'));
    var tbl = el('table', 'tbl');
    var thead = el('thead'); var hr = el('tr');
    ['Name', 'Version', 'Vertical', 'Locale', 'Decoys', 'Tokens', 'Valid'].forEach(function (h) {
      hr.appendChild(el('th', null, h));
    });
    thead.appendChild(hr); tbl.appendChild(thead);
    var tbody = el('tbody');
    (data.packs || []).forEach(function (p) {
      var tr = el('tr', 'clickable');
      tr.appendChild(el('td', null, p.Name));
      tr.appendChild(el('td', 'narrow', p.Version));
      tr.appendChild(el('td', null, p.Vertical || '-'));
      tr.appendChild(el('td', 'narrow', p.Locale || '-'));
      tr.appendChild(el('td', 'narrow', String(p.Decoys)));
      tr.appendChild(el('td', 'narrow', String(p.Tokens)));
      var vTd = el('td', 'narrow');
      vTd.appendChild(el('span', p.Valid ? 't-ok' : 't-err', p.Valid ? 'valid' : 'invalid'));
      tr.appendChild(vTd);
      tr.addEventListener('click', function () { showPackDetail(p.Name); });
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody); body.appendChild(tbl);
    panel.appendChild(body); c.appendChild(panel);
    var host = el('div'); host.id = 'pack-detail-host'; host.style.marginTop = '16px';
    c.appendChild(host);
  });
}

function showPackDetail(name) {
  var host = document.getElementById('pack-detail-host');
  if (!host) return;
  host.replaceChildren(loading());
  tryApi('/api/packs/' + encodeURIComponent(name)).then(function (data) {
    host.replaceChildren();
    if (!data) { host.appendChild(emptyState('Could not load the pack.')); return; }
    var p = data.pack || {};
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Pack: ' + name,
      el('button', 'btn btn-sm btn-secondary', 'Copy apply command')));
    panel.querySelector('button').addEventListener('click', function () {
      copyText('miragectl packs apply ' + name);
    });
    var body = el('div', 'panel-body padded');
    if (p.description) body.appendChild(el('div', 't-sec', p.description));
    (p.decoys || []).forEach(function (d) {
      var svc = (d.services || []).map(function (s) { return s.service + ':' + s.port; }).join(' ');
      body.appendChild(el('div', null, '• ' + d.id + '  (' + d.persona + ')  ' + svc));
    });
    if ((p.honeytokens || []).length) {
      body.appendChild(el('div', 't-muted', 'honeytokens: ' +
        p.honeytokens.map(function (t) { return t.type + '/' + t.label; }).join(', ')));
    }
    panel.appendChild(body); host.appendChild(panel);
  });
}

// ================================================================
// VIEW: IDENTITY / BEC
// ================================================================

function viewIdentity(c) {
  c.replaceChildren();

  // --- SaaS / identity generator ---
  var sp = el('div', 'panel');
  sp.appendChild(panelHead('SaaS / Identity Deception (honey accounts)'));
  var sb = el('div', 'panel-body padded');
  var row = el('div', 'form-row');
  var prov = el('select', 'f-select');
  ['entra', 'okta', 'workspace'].forEach(function (p) { prov.appendChild(new Option(p, p)); });
  var dom = el('input', 'f-input'); dom.placeholder = 'domain (e.g. corp.com)'; dom.value = 'corp.local';
  var genBtn = el('button', 'btn btn-primary', 'Generate');
  row.appendChild(prov); row.appendChild(dom); row.appendChild(genBtn);
  sb.appendChild(row);
  var sOut = el('div'); sOut.style.marginTop = '12px'; sb.appendChild(sOut);
  genBtn.addEventListener('click', function () {
    sOut.replaceChildren(loading());
    api('/api/saasid?provider=' + prov.value + '&domain=' + encodeURIComponent(dom.value)).then(function (d) {
      sOut.replaceChildren();
      var k = d.kit || {};
      var tbl = el('table', 'tbl'); var th = el('thead'); var hr = el('tr');
      ['UPN', 'Role', 'Note'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
      th.appendChild(hr); tbl.appendChild(th);
      var tb = el('tbody');
      (k.accounts || []).forEach(function (a) {
        var tr = el('tr');
        tr.appendChild(el('td', null, a.upn));
        tr.appendChild(el('td', 'narrow', a.role));
        tr.appendChild(el('td', null, a.note));
        tb.appendChild(tr);
      });
      tbl.appendChild(tb); sOut.appendChild(tbl);
      sOut.appendChild(el('div', 't-muted', 'watch in the IdP audit log: ' + (d.watch || []).join(', ')));
    }).catch(function (e) { toast(e.message, 'err'); });
  });
  sp.appendChild(sb); c.appendChild(sp);

  // --- BEC email analysis ---
  var bp = el('div', 'panel'); bp.style.marginTop = '16px';
  bp.appendChild(panelHead('Email / BEC — analyse a received message'));
  var bb = el('div', 'panel-body padded');
  bb.appendChild(el('div', 't-sec', 'Paste a raw email (headers + body) to extract the campaign infrastructure and the BEC tell.'));
  var ta = el('textarea', 'f-input');
  ta.style.width = '100%'; ta.style.minHeight = '140px'; ta.style.marginTop = '10px';
  ta.style.fontFamily = 'var(--mono)'; ta.style.fontSize = '12px';
  ta.placeholder = 'From: ...\\nReply-To: ...\\nSubject: ...\\n\\nbody';
  bb.appendChild(ta);
  var anBtn = el('button', 'btn btn-primary', 'Analyse'); anBtn.style.marginTop = '10px';
  bb.appendChild(anBtn);
  var bOut = el('div'); bOut.style.marginTop = '12px'; bb.appendChild(bOut);
  anBtn.addEventListener('click', function () {
    bOut.replaceChildren(loading());
    api('/api/bec/analyze', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: ta.value })
      .then(function (cmp) {
        bOut.replaceChildren();
        var t = el('table', 'kv');
        kvRow(t, 'from', (cmp.from_name || '') + ' <' + (cmp.from_address || '') + '>');
        kvRow(t, 'reply-to', cmp.reply_to || '-');
        kvRow(t, 'sender IPs', (cmp.sender_ips || []).join(', '));
        kvRow(t, 'URLs', (cmp.urls || []).join(', '));
        bOut.appendChild(t);
        bOut.appendChild(el('div', cmp.is_bec ? 't-err' : 't-ok',
          cmp.is_bec ? 'VERDICT: likely BEC (spoofed sender / external reply)' : 'no BEC tell detected'));
      }).catch(function (e) { toast(e.message, 'err'); });
  });
  bp.appendChild(bb); c.appendChild(bp);
  return Promise.resolve();
}

// ================================================================
// VIEW: BYOD / WIRELESS
// ================================================================

function viewWireless(c) {
  return api('/api/wireless').then(function (data) {
    c.replaceChildren();
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('BYOD / Wireless — honey network devices'));
    var body = el('div', 'panel-body');
    var tbl = el('table', 'tbl'); var th = el('thead'); var hr = el('tr');
    ['Instance', 'Service Type', 'Host', 'Port', 'Kind'].forEach(function (h) { hr.appendChild(el('th', null, h)); });
    th.appendChild(hr); tbl.appendChild(th);
    var tb = el('tbody');
    (data.devices || []).forEach(function (d) {
      var tr = el('tr');
      tr.appendChild(el('td', null, d.instance));
      tr.appendChild(el('td', 'narrow', d.service_type));
      tr.appendChild(el('td', null, d.host));
      tr.appendChild(el('td', 'narrow', String(d.port)));
      tr.appendChild(el('td', 'narrow', d.kind));
      tb.appendChild(tr);
    });
    tbl.appendChild(tb); body.appendChild(tbl);
    var note = el('div', 't-muted padded');
    note.textContent = 'Watch a query for: ' + (data.browse || []).join(', ');
    body.appendChild(note);
    body.appendChild(el('div', 't-sec padded', data.note || ''));
    panel.appendChild(body); c.appendChild(panel);
  });
}

// ================================================================
// VIEW: GLOBAL FEED (anonymized preview)
// ================================================================

function viewFeed(c) {
  return api('/api/feed').then(function (data) {
    c.replaceChildren();
    var panel = el('div', 'panel');
    panel.appendChild(panelHead('Global Feed — anonymized preview',
      el('span', 'tag tag-accent', (data.entries || []).length + ' entries')));
    var body = el('div', 'panel-body');
    body.appendChild(el('div', 't-sec padded', data.note || ''));
    var entries = data.entries || [];
    if (!entries.length) {
      body.appendChild(emptyState('No engagements yet — nothing to share.'));
    } else {
      var tbl = el('table', 'tbl'); var th = el('thead'); var hr = el('tr');
      ['Techniques', 'Services', 'Payload domains', 'Severity', 'Source hash'].forEach(function (h) {
        hr.appendChild(el('th', null, h));
      });
      th.appendChild(hr); tbl.appendChild(th);
      var tb = el('tbody');
      entries.forEach(function (e) {
        var tr = el('tr');
        tr.appendChild(el('td', null, (e.techniques || []).join(', ')));
        tr.appendChild(el('td', null, (e.services || []).join(', ')));
        tr.appendChild(el('td', null, (e.payload_domains || []).join(', ') || '-'));
        tr.appendChild(el('td', 'narrow', e.severity || '-'));
        tr.appendChild(el('td', 'narrow', e.source_hash || '-'));
        tb.appendChild(tr);
      });
      tbl.appendChild(tb); body.appendChild(tbl);
    }
    panel.appendChild(body); c.appendChild(panel);
  });
}

// ================================================================
// VIEW: ALERTING (live sink management + threshold)
// ================================================================

function viewAlerting(c) {
  return api('/api/sinks').then(function (data) {
    c.replaceChildren();

    // --- Threshold ---
    var tp = el('div', 'panel');
    tp.appendChild(panelHead('Alert threshold'));
    var tb = el('div', 'panel-body padded');
    tb.appendChild(el('div', 't-sec',
      'Only events at or above this severity are forwarded (plus honeytoken hits and accepted logins, always). Lower it during an incident, raise it when tuning.'));
    var trow = el('div', 'form-row'); trow.style.marginTop = '10px';
    var sevSel = el('select', 'f-select');
    ['informational', 'low', 'medium', 'high', 'critical', 'fatal'].forEach(function (s) {
      var o = new Option(s, s); if (s === data.min_severity) o.selected = true; sevSel.appendChild(o);
    });
    var setBtn = el('button', 'btn btn-primary', 'Set threshold');
    setBtn.addEventListener('click', function () {
      api('/api/sinks/severity', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ min_severity: sevSel.value }),
      }).then(function (r) { toast('Threshold set to ' + r.min_severity, 'ok'); })
        .catch(function (e) { toast(e.message, 'err'); });
    });
    trow.appendChild(sevSel); trow.appendChild(setBtn);
    tb.appendChild(trow);
    tp.appendChild(tb); c.appendChild(tp);

    // --- Current sinks ---
    var sp = el('div', 'panel'); sp.style.marginTop = '16px';
    sp.appendChild(panelHead('Alert sinks',
      el('button', 'btn btn-sm btn-secondary', 'Send test alert')));
    sp.querySelector('button').addEventListener('click', function () {
      api('/api/sinks/test', { method: 'POST' }).then(function (r) {
        var results = r.results || [];
        if (!results.length) { toast('No sinks configured to test', 'err'); return; }
        results.forEach(function (res) {
          toast(res.sink + ': ' + (res.ok ? 'delivered' : 'FAILED — ' + res.error), res.ok ? 'ok' : 'err');
        });
      }).catch(function (e) { toast(e.message, 'err'); });
    });
    var sb = el('div', 'panel-body');
    sb.appendChild(el('div', 't-sec padded', data.note || ''));
    var sinks = data.sinks || [];
    if (!sinks.length) {
      sb.appendChild(emptyState('No alert sinks. Alarms are recorded in the evidence store but not forwarded anywhere. Add one below.'));
    } else {
      var tbl = el('table', 'tbl'); var th = el('thead'); var hr = el('tr');
      ['Driver', 'Kind', 'Summary', ''].forEach(function (h) { hr.appendChild(el('th', null, h)); });
      th.appendChild(hr); tbl.appendChild(th);
      var tbody = el('tbody');
      sinks.forEach(function (s) {
        var tr = el('tr');
        tr.appendChild(el('td', null, s.name));
        tr.appendChild(el('td', 'narrow', s.kind));
        tr.appendChild(el('td', null, s.summary || '-'));
        var actTd = el('td', 'narrow');
        var rm = el('button', 'btn-link t-err', 'remove');
        rm.addEventListener('click', function () {
          confirmModal('Remove sink', 'Stop forwarding alerts to "' + s.name + '"? Evidence already stored is kept.').then(function (ok) {
            if (!ok) return;
            api('/api/sinks/' + s.index, { method: 'DELETE' }).then(function () {
              toast('Removed ' + s.name, 'ok');
              viewAlerting(c).catch(function (e) { toast(e.message, 'err'); });
            }).catch(function (e) { toast(e.message, 'err'); });
          });
        });
        actTd.appendChild(rm); tr.appendChild(actTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody); sb.appendChild(tbl);
    }
    sp.appendChild(sb); c.appendChild(sp);

    // --- Add a sink ---
    var ap = el('div', 'panel'); ap.style.marginTop = '16px';
    ap.appendChild(panelHead('Add a sink'));
    var ab = el('div', 'panel-body padded');
    ab.appendChild(el('div', 't-sec',
      'Point alarms at a SIEM/webhook live. Config is the driver’s JSON (e.g. webhook: {"url":"https://..."}; syslog: {"address":"host:514"}).'));
    var arow = el('div', 'form-row'); arow.style.marginTop = '10px';
    var drvSel = el('select', 'f-select');
    (data.available || []).forEach(function (d) { drvSel.appendChild(new Option(d, d)); });
    arow.appendChild(drvSel);
    ab.appendChild(arow);
    var cfgTa = el('textarea', 'f-input');
    cfgTa.style.width = '100%'; cfgTa.style.minHeight = '90px'; cfgTa.style.marginTop = '10px';
    cfgTa.style.fontFamily = 'var(--mono)'; cfgTa.style.fontSize = '12px';
    cfgTa.placeholder = '{\n  "url": "https://siem.example/hook"\n}';
    cfgTa.value = '{}';
    ab.appendChild(cfgTa);
    var addBtn = el('button', 'btn btn-primary', 'Add sink'); addBtn.style.marginTop = '10px';
    addBtn.addEventListener('click', function () {
      var cfg;
      try { cfg = JSON.parse(cfgTa.value || '{}'); }
      catch (e) { toast('Config is not valid JSON: ' + e.message, 'err'); return; }
      api('/api/sinks', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ driver: drvSel.value, config: cfg }),
      }).then(function (r) {
        if (r.warning) toast(r.warning, 'err'); else toast('Added ' + r.added + ' sink', 'ok');
        viewAlerting(c).catch(function (e) { toast(e.message, 'err'); });
      }).catch(function (e) { toast(e.message, 'err'); });
    });
    ab.appendChild(addBtn);
    ap.appendChild(ab); c.appendChild(ap);
  });
}

// ================================================================
// INIT
// ================================================================

// Mirror any stored token into the cookie so downloads/navigations carry it
// from the first paint (localStorage survives, the cookie may have expired).
if (storedToken()) setToken(storedToken());

buildNav();
initTableSorting();
loadStatus();
renderView();
scheduleRefresh();
