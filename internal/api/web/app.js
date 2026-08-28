// MIRAGE operator console.
//
// Everything rendered here is attacker-controlled: commands, user agents,
// payloads, file paths, LDAP filters. Nothing is ever inserted as HTML -- only
// as text nodes -- so a captured payload cannot execute in the console an
// analyst is using. The server also sends a strict CSP; this file is the
// second layer, and the one that would actually be tested by an attacker.

const state = {
  engagement: null,     // selected engagement id, used as the event filter
  selectedEvent: null,
  leftView: 'engagements',
  rightView: 'events',
  autorefresh: true,
  timer: null,
  tokenTypes: [],
};

const $ = (id) => document.getElementById(id);

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok && res.status !== 503) {
    throw new Error(`${path}: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function apiText(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.text();
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function ago(ms) {
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

function sevName(id) {
  return ['', 'informational', 'low', 'medium', 'high', 'critical', 'fatal'][id] || 'low';
}

function toast(msg, kind) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast ' + (kind || '');
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 7000);
}

function empty(box, text) {
  box.replaceChildren();
  box.appendChild(el('div', 'empty', text));
}

// ---------------------------------------------------------------- stats

async function loadStats() {
  const s = await api('/api/stats');
  const bar = $('stats');
  bar.replaceChildren();
  const item = (label, value) => {
    const span = el('span', null, label ? label + ' ' : '');
    span.appendChild(el('b', null, value));
    bar.appendChild(span);
  };
  item('events', s.storage.events);
  item('active', s.engagements.active);
  item('sessions', s.live_sessions);
  item('alerts', s.alerts.sent);
  item('tokens', `${s.tokens.triggered}/${s.tokens.total}`);
  item('chain', '#' + s.storage.head_seq);
  item('uptime', s.uptime);
  item('', s.tenant + '/' + s.site);
}

// ---------------------------------------------------------- engagements

async function loadEngagements() {
  const data = await api('/api/engagements?limit=60');
  const box = $('engagements');

  if (!data.engagements.length) {
    empty(box, 'No engagements yet. The decoys are listening.');
    return;
  }
  box.replaceChildren();

  for (const e of data.engagements) {
    const row = el('div', 'row' + (state.engagement === e.id ? ' sel' : ''));
    row.appendChild(el('div', 'sev ' + sevName(e.max_severity)));

    const main = el('div', 'row-main');
    const top = el('div', 'row-top');
    top.appendChild(el('span', 'msg', e.src_ip));
    top.appendChild(el('span', 'time', (e.active ? '' : 'ended ') + ago(Date.parse(e.last_seen))));
    main.appendChild(top);
    main.appendChild(el('div', 'meta', e.summary || 'contact with a decoy'));

    const tags = el('div', 'meta');
    if (e.active) tags.appendChild(el('span', 'badge-live', '● live '));
    for (const s of (e.services || [])) tags.appendChild(el('span', 'tag', s));
    for (const t of (e.techniques || []).slice(0, 4)) tags.appendChild(el('span', 'tag att', t));
    for (const t of (e.honeytokens_hit || [])) tags.appendChild(el('span', 'tag tok', 'token:' + t));
    main.appendChild(tags);
    row.appendChild(main);

    const risk = el('div', 'risk ' + (e.risk_score >= 70 ? 'r-hi' : e.risk_score >= 35 ? 'r-md' : 'r-lo'), e.risk_score);
    risk.title = 'risk score';
    row.appendChild(risk);

    row.addEventListener('click', () => {
      state.engagement = state.engagement === e.id ? null : e.id;
      if (state.rightView === 'detections') loadDetections().catch(showError);
      refresh();
    });
    box.appendChild(row);
  }
}

// -------------------------------------------------------------- tokens

async function loadTokens() {
  const data = await api('/api/tokens');
  if (state.tokenTypes.length === 0 && data.types) {
    state.tokenTypes = data.types;
    const sel = $('token-type');
    sel.replaceChildren();
    for (const t of data.types) sel.appendChild(new Option(t, t));
  }

  const box = $('tokens');
  if (!data.tokens.length) {
    empty(box, 'No honeytokens yet. Mint one above and plant it.');
    return;
  }
  box.replaceChildren();

  for (const t of data.tokens) {
    const row = el('div', 'row');
    row.appendChild(el('div', 'sev ' + (t.triggers > 0 ? 'critical' : 'low')));

    const main = el('div', 'row-main');
    const top = el('div', 'row-top');
    top.appendChild(el('span', 'msg', t.label || t.id));
    top.appendChild(el('span', t.triggers > 0 ? 'fired' : 'time',
      t.triggers > 0 ? `${t.triggers}x triggered` : 'quiet'));
    main.appendChild(top);
    main.appendChild(el('div', 'mono', t.value));

    const meta = el('div', 'meta');
    meta.appendChild(el('span', 'tag', t.type));
    if (t.location) meta.appendChild(el('span', 'tag', t.location));
    if (t.type === 'office-doc' || t.type === 'url' || t.type === 'web-image') {
      const a = el('a', 'dl', 'bait .docx');
      a.href = `/api/tokens/${encodeURIComponent(t.id)}/docx`;
      meta.appendChild(a);
    }
    main.appendChild(meta);
    row.appendChild(main);
    box.appendChild(row);
  }
}

async function mintToken() {
  const type = $('token-type').value;
  if (!type) return;
  try {
    await api('/api/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type,
        label: $('token-label').value.trim(),
        location: $('token-location').value.trim(),
      }),
    });
    $('token-label').value = '';
    $('token-location').value = '';
    toast(`minted a ${type} token — plant it and wait`, 'good');
    await loadTokens();
  } catch (err) {
    showError(err);
  }
}

// -------------------------------------------------------------- decoys

async function loadDecoys() {
  const data = await api('/api/decoys');
  const box = $('decoys');
  const bound = data.bound || [];
  if (!bound.length) {
    empty(box, 'No decoys are listening.');
    return;
  }
  box.replaceChildren();

  const byDecoy = new Map();
  for (const l of bound) {
    if (!byDecoy.has(l.decoy_id)) byDecoy.set(l.decoy_id, []);
    byDecoy.get(l.decoy_id).push(l);
  }

  for (const [decoyID, listeners] of byDecoy) {
    const persona = listeners[0].persona;
    const info = (data.personas || {})[persona] || {};
    const row = el('div', 'row');
    row.appendChild(el('div', 'sev low'));

    const main = el('div', 'row-main');
    const top = el('div', 'row-top');
    top.appendChild(el('span', 'msg', `${decoyID} — ${info.hostname || persona}`));
    top.appendChild(el('span', 'time', info.uptime_days ? `up ${info.uptime_days}d` : ''));
    main.appendChild(top);
    main.appendChild(el('div', 'meta', info.os || persona));

    const ports = el('div', 'meta');
    for (const l of listeners) {
      ports.appendChild(el('span', 'tag', `${l.service} ${l.address}/${l.proto}`));
    }
    main.appendChild(ports);
    row.appendChild(main);
    box.appendChild(row);
  }
}


// --------------------------------------------------------------- infrastructure

async function loadInfra() {
  const box = $('infra');
  const [vms, presence] = await Promise.all([
    api('/api/vms').catch(() => ({ enabled: false, decoys: [] })),
    api('/api/presence').catch(() => ({ enabled: false, agents: [] })),
  ]);
  box.replaceChildren();

  if (vms.enabled && (vms.decoys || []).length) {
    box.appendChild(el('div', 'section-head', 'Full-OS decoys'));
    for (const d of vms.decoys) {
      const row = el('div', 'row');
      const burned = d.burned;
      row.appendChild(el('div', 'sev ' + (burned ? 'high' : 'low')));
      const main = el('div', 'row-main');
      const top = el('div', 'row-top');
      top.appendChild(el('span', 'msg', `${d.id} — ${d.persona}`));
      top.appendChild(el('span', 'time', d.state));
      main.appendChild(top);
      const meta = el('div', 'meta');
      meta.appendChild(el('span', 'tag', d.template || 'vm'));
      if (d.baseline) meta.appendChild(el('span', 'tag', 'baseline'));
      if (d.revert && d.revert !== 'never') meta.appendChild(el('span', 'tag', 'reset: ' + d.revert));
      if (burned) meta.appendChild(el('span', 'tag bad', 'BURNED: ' + (d.burn_reason || '')));
      main.appendChild(meta);

      if (!burned) {
        const actions = el('div', 'meta');
        const burn = el('button', 'link', 'burn');
        burn.title = 'Take this decoy out of service and preserve it as evidence. It is never restarted.';
        burn.addEventListener('click', () => vmAction(d.id, 'burn'));
        actions.appendChild(burn);
        if (vms.can_revert) {
          const reset = el('button', 'link', 'reset');
          reset.title = 'Return this decoy to its clean baseline, snapshotting the dirty state first.';
          reset.addEventListener('click', () => vmAction(d.id, 'revert'));
          actions.appendChild(reset);
        }
        main.appendChild(actions);
      }
      row.appendChild(main);
      box.appendChild(row);
    }
  }

  if (presence.enabled) {
    box.appendChild(el('div', 'section-head', 'Overlay agents'));
    const agents = presence.agents || [];
    if (!agents.length) {
      const row = el('div', 'row');
      row.appendChild(el('div', 'sev low'));
      row.appendChild(el('div', 'row-main', 'No agents connected. The hub is listening at ' + (presence.hub || '?') + '.'));
      box.appendChild(row);
    }
    for (const a of agents) {
      const row = el('div', 'row');
      row.appendChild(el('div', 'sev low'));
      const main = el('div', 'row-main');
      const top = el('div', 'row-top');
      top.appendChild(el('span', 'msg', `${a.id} — ${a.persona}`));
      top.appendChild(el('span', 'time', a.remote || ''));
      main.appendChild(top);
      const meta = el('div', 'meta');
      meta.appendChild(el('span', 'tag', 'decoy ' + (a.decoy_id || '')));
      for (const svc of (a.services || [])) meta.appendChild(el('span', 'tag', svc));
      main.appendChild(meta);
      row.appendChild(main);
      box.appendChild(row);
    }
  }

  if (!box.childNodes.length) {
    empty(box, 'No full-OS decoys or overlay agents in this deployment.');
  }
}

async function vmAction(id, action) {
  const label = action === 'burn' ? 'burning' : 'resetting';
  toast(`${label} ${id}...`);
  try {
    const r = await api(`/api/vms/${encodeURIComponent(id)}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'from the operator console' }),
    });
    toast(`${action}: ${r.id}`, 'good');
    loadInfra().catch(showError);
  } catch (err) {
    showError(err);
  }
}

// --------------------------------------------------------------- events

function eventQuery() {
  const p = new URLSearchParams();
  p.set('limit', '200');
  const q = $('q').value.trim();
  if (q) p.set('q', q);
  const sev = $('severity').value;
  if (sev) p.set('severity', sev);
  if (state.engagement) return `/api/engagements/${encodeURIComponent(state.engagement)}/events?${p}`;
  return `/api/events?${p}`;
}

async function loadEvents() {
  const data = await api(eventQuery());
  const box = $('events');

  $('context-label').textContent = state.engagement ? 'engagement ' + state.engagement : 'all events';
  $('clear-filter').hidden = !state.engagement;
  $('tab-detections').disabled = !state.engagement;

  if (!data.events.length) {
    empty(box, 'Nothing matches.');
    return;
  }
  box.replaceChildren();

  // Newest first, except inside an engagement where the story reads forward.
  const events = state.engagement ? data.events.slice().reverse() : data.events;

  for (const ev of events) {
    const row = el('div', 'row' + (state.selectedEvent === ev.metadata.uid ? ' sel' : ''));
    row.appendChild(el('div', 'sev ' + sevName(ev.severity_id)));

    const main = el('div', 'row-main');
    const top = el('div', 'row-top');
    top.appendChild(el('span', 'msg', ev.message || ev.class_uid));
    top.appendChild(el('span', 'time', ago(ev.time)));
    main.appendChild(top);

    const meta = el('div', 'meta');
    meta.appendChild(el('span', 'tag', ev.mirage.service || 'system'));
    meta.appendChild(el('span', 'tag', ev.src_endpoint ? ev.src_endpoint.ip : '-'));
    if (ev.mirage.decoy_id) meta.appendChild(el('span', 'tag', ev.mirage.decoy_id));
    for (const t of (ev.mirage.attack || [])) {
      meta.appendChild(el('span', 'tag att', t.technique + (t.name ? ' ' + t.name : '')));
    }
    if (ev.unmapped && ev.unmapped.honeytoken) meta.appendChild(el('span', 'tag tok', 'honeytoken'));
    main.appendChild(meta);
    row.appendChild(main);

    row.addEventListener('click', () => showDetail(ev));
    box.appendChild(row);
  }
}

// ----------------------------------------------------------- detections

async function loadDetections() {
  const box = $('detections');
  const head = $('detect-summary');
  for (const id of ['dl-sigma', 'dl-suricata', 'dl-yara', 'dl-stix', 'dl-report']) {
    $(id).hidden = true;
  }
  if (!state.engagement) {
    head.textContent = 'Select an engagement to generate detection content from it.';
    empty(box, 'No engagement selected.');
    return;
  }

  const bundle = await api(`/api/engagements/${encodeURIComponent(state.engagement)}/forge`);
  head.textContent =
    `${bundle.rules.length} rule(s) and ${(bundle.iocs || []).length} indicator(s) ` +
    `from engagement ${state.engagement}`;

  const base = `/api/engagements/${encodeURIComponent(state.engagement)}/forge?format=`;
  for (const [id, fmt] of [['dl-sigma', 'sigma'], ['dl-suricata', 'suricata'],
                           ['dl-yara', 'yara'], ['dl-stix', 'stix'], ['dl-report', 'report']]) {
    const a = $(id);
    a.href = base + fmt;
    a.target = '_blank';
    a.rel = 'noopener';
    a.hidden = false;
  }

  box.replaceChildren();
  if (!bundle.rules.length) {
    box.appendChild(el('div', 'empty', 'Nothing in this engagement was specific enough to signature.'));
  }
  for (const r of bundle.rules) {
    const item = el('div', 'rule');
    const h = el('h4', null, r.title);
    h.appendChild(el('span', 'tag', ' ' + r.format));
    if (r.technique) h.appendChild(el('span', 'tag att', r.technique));
    item.appendChild(h);
    item.appendChild(el('p', 'why', r.rationale));
    item.appendChild(el('pre', null, r.content));
    box.appendChild(item);
  }

  if ((bundle.rejected || []).length) {
    const note = el('div', 'rejected');
    note.appendChild(el('b', null, 'Deliberately not turned into rules. '));
    note.appendChild(document.createTextNode(
      'A rule that fires on normal activity gets the whole feed switched off.'));
    for (const rj of bundle.rejected) {
      const line = el('div', null, `${rj.candidate} — ${rj.reason}`);
      note.appendChild(line);
    }
    box.appendChild(note);
  }
}

// --------------------------------------------------------------- detail

function showDetail(ev) {
  state.selectedEvent = ev.metadata.uid;
  $('detail-title').textContent = ev.message || ev.class_uid;
  const body = $('detail-body');
  body.replaceChildren();

  const facts = [
    ['time', new Date(ev.time).toISOString()],
    ['severity', sevName(ev.severity_id)],
    ['class', ev.class_uid],
    ['plane', ev.mirage.source_plane],
    ['decoy', ev.mirage.decoy_id],
    ['persona', ev.mirage.decoy_persona],
    ['service', ev.mirage.service],
    ['engagement', ev.mirage.engagement_id],
    ['source', ev.src_endpoint ? `${ev.src_endpoint.ip}:${ev.src_endpoint.port}` : ''],
    ['destination', ev.dst_endpoint ? `${ev.dst_endpoint.ip}:${ev.dst_endpoint.port}` : ''],
    ['chain seq', ev.mirage.chain ? ev.mirage.chain.seq : ''],
    ['chain hash', ev.mirage.chain ? ev.mirage.chain.hash : ''],
    ['event uid', ev.metadata.uid],
  ];
  body.appendChild(el('h3', null, 'event'));
  const t = el('table');
  for (const [k, v] of facts) {
    if (!v) continue;
    const tr = el('tr');
    tr.appendChild(el('td', 'k', k));
    tr.appendChild(el('td', null, v));
    t.appendChild(tr);
  }
  body.appendChild(t);

  if ((ev.mirage.attack || []).length) {
    body.appendChild(el('h3', null, 'ATT&CK'));
    const box = el('div');
    for (const a of ev.mirage.attack) {
      box.appendChild(el('span', 'tag att', `${a.tactic || ''} ${a.technique} ${a.name || ''}`.trim()));
    }
    body.appendChild(box);
  }

  const data = ev.unmapped || {};
  if (data.transcript) {
    body.appendChild(el('h3', null, 'session transcript'));
    body.appendChild(el('pre', null, data.transcript));
  }
  const rest = Object.entries(data).filter(([k]) => k !== 'transcript');
  if (rest.length) {
    body.appendChild(el('h3', null, 'details'));
    const dt = el('table');
    for (const [k, v] of rest) {
      const tr = el('tr');
      tr.appendChild(el('td', 'k', k));
      const val = typeof v === 'string' ? v : JSON.stringify(v);
      const td = el('td');
      if (val.length > 200 || val.includes('\n')) td.appendChild(el('pre', null, val));
      else td.textContent = val;
      tr.appendChild(td);
      dt.appendChild(tr);
    }
    body.appendChild(dt);
  }

  $('detail').hidden = false;
  loadEvents().catch(() => {});
}

// --------------------------------------------------------------- wiring

function showError(err) { toast(String(err.message || err), 'bad'); }

function switchView(side, view) {
  const tabs = side === 'left' ? $('left-tabs') : $('right-tabs');
  for (const tab of tabs.querySelectorAll('.tab')) {
    tab.classList.toggle('active', tab.dataset.view === view);
  }
  const views = side === 'left'
    ? ['engagements', 'tokens', 'decoys', 'infra']
    : ['events', 'detections'];
  for (const v of views) $('view-' + v).hidden = v !== view;

  if (side === 'left') state.leftView = view; else state.rightView = view;
  refresh().catch(showError);
}

for (const [tabsID, side] of [['left-tabs', 'left'], ['right-tabs', 'right']]) {
  $(tabsID).addEventListener('click', (e) => {
    const tab = e.target.closest('.tab');
    if (tab && !tab.disabled) switchView(side, tab.dataset.view);
  });
}

async function refresh() {
  const jobs = [loadStats()];
  if (state.leftView === 'engagements') jobs.push(loadEngagements());
  if (state.leftView === 'tokens') jobs.push(loadTokens());
  if (state.leftView === 'decoys') jobs.push(loadDecoys());
  if (state.leftView === 'infra') jobs.push(loadInfra());
  if (state.rightView === 'events') jobs.push(loadEvents());
  if (state.rightView === 'detections') jobs.push(loadDetections());
  try {
    await Promise.all(jobs);
  } catch (err) {
    showError(err);
  }
}

function scheduleRefresh() {
  clearInterval(state.timer);
  // The detections view is generated on demand and does not change on its own,
  // so refreshing it on a timer would only fight the analyst's scroll position.
  if (state.autorefresh) state.timer = setInterval(() => {
    if (state.rightView === 'detections') return;
    refresh();
  }, 3000);
}

$('autorefresh').addEventListener('change', (e) => {
  state.autorefresh = e.target.checked;
  scheduleRefresh();
});
$('clear-filter').addEventListener('click', () => {
  state.engagement = null;
  if (state.rightView === 'detections') switchView('right', 'events');
  else refresh();
});
$('detail-close').addEventListener('click', () => {
  $('detail').hidden = true;
  state.selectedEvent = null;
  loadEvents().catch(() => {});
});
$('severity').addEventListener('change', () => loadEvents().catch(showError));
$('token-mint').addEventListener('click', mintToken);

let debounce;
$('q').addEventListener('input', () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => loadEvents().catch(showError), 250);
});

$('verify').addEventListener('click', async () => {
  toast('replaying the evidence chain...');
  try {
    const r = await api('/api/evidence/verify', { method: 'POST' });
    if (r.verified) {
      toast(`evidence intact: ${r.events} events, head #${r.head_seq}, ${r.took}`, 'good');
    } else {
      toast('EVIDENCE TAMPERED: ' + r.error, 'bad');
    }
  } catch (err) {
    showError(err);
  }
});

$('selftest').addEventListener('click', async () => {
  toast('attacking the decoys and checking what was recorded...');
  try {
    const r = await api('/api/assure', { method: 'POST' });
    toast(r.summary, r.healthy ? 'good' : 'bad');
  } catch (err) {
    showError(err);
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') $('detail-close').click();
});

refresh();
scheduleRefresh();
