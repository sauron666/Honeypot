// MIRAGE operator console.
//
// Everything rendered here is attacker-controlled: commands, user agents,
// payloads, file paths. Nothing is ever inserted as HTML -- only as text
// nodes -- so a payload cannot execute in the console an analyst is using.
// The server also sends a strict CSP; this file is the second layer.

const state = {
  engagement: null,   // filter: engagement id
  selectedEvent: null,
  autorefresh: true,
  timer: null,
};

const $ = (id) => document.getElementById(id);

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path}: ${res.status} ${res.statusText}`);
  return res.json();
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
  toast._t = setTimeout(() => { t.hidden = true; }, 6000);
}

// ---------------------------------------------------------------- stats

async function loadStats() {
  const s = await api('/api/stats');
  const bar = $('stats');
  bar.replaceChildren();
  const item = (label, value) => {
    const span = el('span', null, label + ' ');
    span.appendChild(el('b', null, value));
    bar.appendChild(span);
  };
  item('events', s.storage.events);
  item('active', s.engagements.active);
  item('sessions', s.live_sessions);
  item('alerts', s.alerts.sent);
  item('suppressed', s.alerts.suppressed);
  item('chain', '#' + s.storage.head_seq);
  item('uptime', s.uptime);
  item('', s.tenant + '/' + s.site);
}

// ---------------------------------------------------------- engagements

async function loadEngagements() {
  const data = await api('/api/engagements?limit=60');
  const box = $('engagements');
  box.replaceChildren();

  if (!data.engagements.length) {
    box.appendChild(el('div', 'empty', 'No engagements yet. The decoys are listening.'));
    return;
  }

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
      refresh();
    });
    box.appendChild(row);
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
  box.replaceChildren();

  $('filter-label').textContent = state.engagement ? 'engagement ' + state.engagement : 'all';
  $('clear-filter').hidden = !state.engagement;

  if (!data.events.length) {
    box.appendChild(el('div', 'empty', 'Nothing matches.'));
    return;
  }
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
    const src = ev.src_endpoint ? ev.src_endpoint.ip : '-';
    meta.appendChild(el('span', 'tag', ev.mirage.service || 'system'));
    meta.appendChild(el('span', 'tag', src));
    if (ev.mirage.decoy_id) meta.appendChild(el('span', 'tag', ev.mirage.decoy_id));
    for (const t of (ev.mirage.attack || [])) {
      meta.appendChild(el('span', 'tag att', t.technique + (t.name ? ' ' + t.name : '')));
    }
    if (ev.unmapped && ev.unmapped.honeytoken) {
      meta.appendChild(el('span', 'tag tok', 'honeytoken'));
    }
    main.appendChild(meta);
    row.appendChild(main);

    row.addEventListener('click', () => showDetail(ev));
    box.appendChild(row);
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
  // The transcript is the recording of the session; it deserves its own block.
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

async function refresh() {
  try {
    await Promise.all([loadStats(), loadEngagements(), loadEvents()]);
  } catch (err) {
    toast(String(err.message || err), 'bad');
  }
}

function scheduleRefresh() {
  clearInterval(state.timer);
  if (state.autorefresh) state.timer = setInterval(refresh, 3000);
}

$('autorefresh').addEventListener('change', (e) => {
  state.autorefresh = e.target.checked;
  scheduleRefresh();
});
$('clear-filter').addEventListener('click', () => { state.engagement = null; refresh(); });
$('detail-close').addEventListener('click', () => {
  $('detail').hidden = true;
  state.selectedEvent = null;
  loadEvents().catch(() => {});
});
$('severity').addEventListener('change', () => loadEvents().catch((e) => toast(String(e), 'bad')));

let debounce;
$('q').addEventListener('input', () => {
  clearTimeout(debounce);
  debounce = setTimeout(() => loadEvents().catch((e) => toast(String(e), 'bad')), 250);
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
    toast(String(err.message || err), 'bad');
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') $('detail-close').click();
});

refresh();
scheduleRefresh();
