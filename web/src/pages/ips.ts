// The IPS page (2026-10-27): what the router's nDPI sensor classifies, what the
// rules made of it, the rules, and the sensor's setup.
//
// ── ASKED FOR WHILE SHOWN ───────────────────────────────────────────────────
//
// The engine runs on the server whether or not anybody looks
// (internal/server/ips.go); this page asks GET /api/ips/state every POLL_MS
// while it is the page shown, and not at all otherwise. Nothing here reads the
// router except the Setup tab's buttons and "Read the lists", which the
// operator presses.
//
// ── ADMINISTRATORS CHANGE IT ────────────────────────────────────────────────
//
// The rules and the sensor are for administrators (the state says `admin`);
// everybody with the page's read grant sees the flows and the decisions.

import { el, esc, pill, protoPill, renderSortHeader, sortRows, copyText, type SortState } from '../dom';
import type { PillTone } from '../palette';
import type { Socket } from '../socket';
import { fmtTime } from '../timefmt';

const POLL_MS = 3000;

interface Flow {
  ts: number; l4: string; client: string; clientPort: number; server: string; serverPort: number;
  name: string; app: string; master: string; category: string; breed: string; host: string;
  risks: string[]; guessed: boolean; packets: number; bytes: number;
  action: string; rule: string; result: string;
}
interface AppCount { name: string; category: string; flows: number; bytes: number }
interface Stats { packets: number; bytes: number; flows: number; active: number; droppedEvents: number }
interface Status {
  state: string; message: string; since: number; sensor: string; ndpi: string; enforce: boolean;
  stats: Stats | null; seen: number; listed: number; refused: number; limited: number; failed: number;
}
interface Rule {
  id: number; name: string; enabled: boolean; apps: string[]; categories: string[]; breeds: string[];
  risks: string[]; hosts: string[]; clients: string[]; action: string; timeoutMin: number;
}
interface Event {
  id: number; ts: number; ruleName: string; action: string; result: string; target: string;
  client: string; server: string; serverPort: number; l4: string; app: string; host: string;
}
interface Sensor {
  address: string; enforce: boolean; sniffBytes: number; protected: string[]; disk: string; image: string;
}
interface State {
  configured: boolean; sensor: Sensor | null; status: Status; flows: Flow[]; apps: AppCount[];
  events: Event[]; rules: Rule[]; admin: boolean; defaults: { sniffBytes: number; image: string; timeoutMin: number };
}
interface Step { op: string; menu: string; what: string; error?: string }
interface Listed { id: string; list: string; address: string; timeout: string; comment: string }

function call<T>(url: string, init?: RequestInit): Promise<T> {
  return fetch(url, { credentials: 'same-origin', ...init }).then((r) =>
    r.json().then((d) => (r.ok ? d as T : Promise.reject(new Error((d && d.error) || r.statusText)))));
}

function post<T>(url: string, body?: unknown): Promise<T> {
  return call<T>(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
}

/** The tone of each action, shared by every table that shows one. */
export const ACTION_TONE: Record<string, PillTone> = { block: 'err', quarantine: 'warn', log: 'rx', allow: 'ok' };

/** The tone of what became of a decision. */
export function resultTone(r: string): PillTone {
  if (r === 'listed') return 'err';
  if (r === 'monitor' || r === 'logged' || r === 'already' || r === 'queued') return 'muted';
  if (r === 'limited' || r.indexOf('refused') === 0) return 'warn';
  return r === 'failed' ? 'err' : 'muted';
}

/** The sensor's state, as the header shows it. */
export function statePill(st: Status): string {
  const tone: Record<string, PillTone> = { connected: 'ok', connecting: 'muted', unreachable: 'err', refused: 'err', off: 'muted' };
  const word: Record<string, string> = { connected: 'sensor up', connecting: 'connecting', unreachable: 'sensor unreachable',
    refused: 'token refused', off: 'no sensor' };
  return pill(word[st.state] || st.state, tone[st.state] || 'muted');
}

/** A rule's criteria in one line. */
export function ruleSummary(r: Rule): string {
  const parts: string[] = [];
  const add = (label: string, v: string[]): void => { if (v.length) parts.push(label + ' ' + v.join(', ')); };
  add('app', r.apps);
  add('category', r.categories);
  add('breed', r.breeds);
  add('risk', r.risks);
  add('host', r.hosts);
  add('from', r.clients);
  return parts.join(' · ');
}

function splitList(v: string): string[] {
  return v.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
}

function fmtCount(n: number | null | undefined): string {
  if (n == null) return '-';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

function fmtVol(b: number): string {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' kB';
  return b + ' B';
}

export function initIpsPage(socket: Socket, isVisible: (page: string) => boolean): void {
  let routerId = '';
  let state: State | null = null;
  let timer: ReturnType<typeof setInterval> | null = null;
  let tab = 'flows';
  let flowFilter = '';
  let matchedOnly = false;
  let editing: Rule | null = null;
  let formFilledFor = '';
  const flowSort: SortState = { col: 'ts', dir: 'desc' };
  const appSort: SortState = { col: 'flows', dir: 'desc' };
  const eventSort: SortState = { col: 'ts', dir: 'desc' };
  const listedSort: SortState = { col: 'address', dir: 'asc' };

  const setText = (id: string, t: string): void => { const n = el(id); if (n) n.textContent = t; };
  const setHTML = (id: string, h: string): void => { const n = el(id); if (n) n.innerHTML = h; };
  const q = (id: string): string => (el<HTMLInputElement>(id)?.value || '').trim();
  const qs = (): string => '?router=' + encodeURIComponent(routerId);

  function load(): void {
    if (!routerId || !isVisible('ips')) return;
    const asked = routerId;
    call<State>('/api/ips/state' + qs())
      .then((s) => { if (asked === routerId) { state = s; draw(); } })
      .catch((e: Error) => setText('ipsStatus', e.message));
  }

  function drawCards(s: State): void {
    const st = s.status;
    setHTML('ipsStatePill', statePill(st));
    setHTML('ipsModePill', s.configured ? (st.enforce || s.sensor?.enforce ? pill('enforcing', 'err') : pill('watching', 'rx')) : '');
    let note = '';
    if (!s.configured) note = s.admin ? 'No sensor on this router yet: open Setup.' : 'No sensor on this router yet.';
    else if (st.state !== 'connected') note = st.message || 'Waiting for the sensor at ' + st.sensor + '.';
    else if (st.ndpi) note = 'nDPI ' + st.ndpi + ' at ' + st.sensor;
    setText('ipsStatus', note);
    setText('ipsSeenVal', fmtCount(st.seen));
    setText('ipsListedVal', fmtCount(st.listed));
    const issues = [st.refused ? st.refused + ' refused' : '', st.limited ? st.limited + ' limited' : '',
      st.failed ? st.failed + ' failed' : ''].filter(Boolean).join(', ');
    setText('ipsListedFoot', issues);
    setText('ipsPacketsVal', fmtCount(st.stats?.packets));
    setText('ipsPacketsFoot', st.stats ? fmtVol(st.stats.bytes) + (st.stats.droppedEvents ? ', ' + st.stats.droppedEvents + ' events lost' : '') : '');
    const top = s.apps[0];
    setText('ipsTopVal', top ? top.name : '-');
    setText('ipsTopFoot', top ? top.flows + ' flows, ' + fmtVol(top.bytes) : '');
  }

  function drawFlows(s: State): void {
    const f = flowFilter.toLowerCase();
    const rows = s.flows.filter((x) => (!matchedOnly || x.action) && (!f ||
      [x.client, x.server, x.name, x.host, x.category].some((v) => v.toLowerCase().indexOf(f) !== -1)));
    renderSortHeader('ipsFlowsHead', [
      { key: 'ts', label: 'Time' }, { key: 'l4', label: 'Proto' }, { key: 'client', label: 'Client' },
      { key: 'server', label: 'Server' }, { key: 'name', label: 'Application' }, { key: 'category', label: 'Category' },
      { key: 'host', label: 'Host' }, { key: 'action', label: 'Decision' },
    ], flowSort, () => drawFlows(s));
    const sorted = sortRows(rows, flowSort.col, flowSort.dir);
    setHTML('ipsFlowsRows', sorted.length ? sorted.map((x) => '<tr>' +
      '<td>' + esc(fmtTime(x.ts)) + '</td>' +
      '<td>' + protoPill(x.l4) + '</td>' +
      '<td>' + esc(x.client) + '</td>' +
      '<td>' + esc(x.server) + ':' + x.serverPort + '</td>' +
      '<td>' + pill(x.name || 'Unknown', x.guessed ? 'muted' : 'alt') +
        (x.risks.length ? ' ' + '<span title="' + esc(x.risks.join(', ')) + '">' + pill(x.risks.length + ' risk' + (x.risks.length > 1 ? 's' : ''), 'warn') + '</span>' : '') + '</td>' +
      '<td>' + esc(x.category || '-') + '</td>' +
      '<td>' + esc(x.host || '-') + '</td>' +
      '<td>' + (x.action ? pill(x.action, ACTION_TONE[x.action] || 'muted') + ' ' + pill(x.result, resultTone(x.result)) : '-') + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="8" class="empty-state">' + (s.flows.length ? 'No flow matches' : 'No flows yet') + '</td></tr>');
  }

  function drawApps(s: State): void {
    renderSortHeader('ipsAppsHead', [
      { key: 'name', label: 'Application' }, { key: 'category', label: 'Category' },
      { key: 'flows', label: 'Flows' }, { key: 'bytes', label: 'Inspected' },
    ], appSort, () => drawApps(s));
    const sorted = sortRows(s.apps, appSort.col, appSort.dir);
    setHTML('ipsAppsRows', sorted.length ? sorted.map((a) => '<tr><td>' + pill(a.name, 'alt') + '</td><td>' +
      esc(a.category || '-') + '</td><td>' + a.flows + '</td><td>' + fmtVol(a.bytes) + '</td></tr>').join('')
      : '<tr><td colspan="4" class="empty-state">No flows yet</td></tr>');
  }

  function drawEvents(s: State): void {
    renderSortHeader('ipsEventsHead', [
      { key: 'ts', label: 'Time' }, { key: 'ruleName', label: 'Rule' }, { key: 'action', label: 'Action' },
      { key: 'result', label: 'Result' }, { key: 'target', label: 'Listed' }, { key: 'app', label: 'Application' },
      { key: 'client', label: 'Flow' },
    ], eventSort, () => drawEvents(s));
    const sorted = sortRows(s.events, eventSort.col, eventSort.dir);
    setHTML('ipsEventsRows', sorted.length ? sorted.map((e) => '<tr>' +
      '<td>' + esc(fmtTime(e.ts)) + '</td><td>' + esc(e.ruleName) + '</td>' +
      '<td>' + pill(e.action, ACTION_TONE[e.action] || 'muted') + '</td>' +
      '<td>' + pill(e.result, resultTone(e.result)) + '</td>' +
      '<td>' + esc(e.target || '-') + '</td><td>' + esc(e.app) + (e.host ? ' <span class="muted-note">' + esc(e.host) + '</span>' : '') + '</td>' +
      '<td>' + esc(e.client) + ' → ' + esc(e.server) + ':' + e.serverPort + '</td></tr>').join('')
      : '<tr><td colspan="7" class="empty-state">No decisions yet</td></tr>');
  }

  // AN ORDERED TABLE: the first match decides, so it keeps its order and has
  // move arrows instead of sortable headers (CLAUDE.md, the Queues page's rule).
  function drawRules(s: State): void {
    const admin = s.admin;
    setHTML('ipsRulesRows', s.rules.length ? s.rules.map((r, i) => '<tr>' +
      '<td>' + (i + 1) + '</td><td>' + esc(r.name) + '</td>' +
      '<td>' + esc(ruleSummary(r)) + '</td>' +
      '<td>' + pill(r.action, ACTION_TONE[r.action] || 'muted') + '</td>' +
      '<td>' + (r.timeoutMin ? r.timeoutMin + ' min' : '-') + '</td>' +
      '<td>' + (r.enabled ? pill('enabled', 'ok') : pill('disabled', 'muted')) + '</td>' +
      '<td class="text-end">' + (admin
        ? '<button class="sbtn sbtn-ghost" type="button" data-ipsmove="' + r.id + '" data-dir="-1"' + (i === 0 ? ' disabled' : '') + ' title="Up">↑</button> ' +
          '<button class="sbtn sbtn-ghost" type="button" data-ipsmove="' + r.id + '" data-dir="1"' + (i === s.rules.length - 1 ? ' disabled' : '') + ' title="Down">↓</button> ' +
          '<button class="sbtn sbtn-outline" type="button" data-ipsedit="' + r.id + '">Edit</button> ' +
          '<button class="sbtn sbtn-danger" type="button" data-ipsdel="' + r.id + '">Delete</button>'
        : '') + '</td></tr>').join('')
      : '<tr><td colspan="7" class="empty-state">No rules: every flow is only counted</td></tr>');
    const addWrap = el('ipsRuleAddWrap');
    if (addWrap) addWrap.style.display = admin && !editing ? '' : 'none';
  }

  function fillSensorForm(s: State): void {
    // Filled once per router, so a poll does not overwrite what is being typed.
    if (formFilledFor === routerId) return;
    formFilledFor = routerId;
    const sn = s.sensor;
    const set = (id: string, v: string): void => { const n = el<HTMLInputElement>(id); if (n) n.value = v; };
    set('ipsSensorAddress', sn?.address || '');
    set('ipsSensorBytes', sn ? String(sn.sniffBytes) : '');
    set('ipsSensorDisk', sn?.disk || '');
    set('ipsSensorImage', sn?.image || '');
    set('ipsSensorProtected', (sn?.protected || []).join('\n'));
    const enf = el<HTMLInputElement>('ipsSensorEnforce');
    if (enf) enf.checked = !!sn?.enforce;
    const img = el<HTMLInputElement>('ipsSensorImage');
    if (img) img.placeholder = s.defaults.image;
  }

  function drawSetup(s: State): void {
    setText('ipsSetupNote', s.admin
      ? 'The sensor runs as a container on the router. Save it here, create the container, then apply the rules.'
      : 'The IPS is configured by administrators.');
    for (const id of ['ipsSensorForm', 'ipsScriptShow', 'ipsScriptCopy', 'ipsPlanShow', 'ipsApply', 'ipsRemove']) {
      const n = el(id);
      if (n) n.style.display = s.admin ? '' : 'none';
    }
    el('ipsSensorDelete')?.toggleAttribute('disabled', !s.configured);
    el('ipsSensorToken')?.toggleAttribute('disabled', !s.configured);
    fillSensorForm(s);
  }

  function draw(): void {
    if (!state) return;
    const s = state;
    drawCards(s);
    const badge = el('ipsBadge');
    if (badge) {
      badge.textContent = String(s.flows.length);
      badge.className = 'card-badge' + (s.flows.length ? ' active-blue' : '');
    }
    if (tab === 'flows') drawFlows(s);
    if (tab === 'apps') drawApps(s);
    if (tab === 'events') drawEvents(s);
    drawRules(s);
    drawSetup(s);
  }

  function clear(): void {
    state = null;
    formFilledFor = '';
    editing = null;
    showEditor(false);
    for (const id of ['ipsStatePill', 'ipsModePill', 'ipsScript']) setHTML(id, '');
    setText('ipsStatus', '');
    setHTML('ipsFlowsRows', '<tr><td colspan="8" class="empty-state">No flows yet</td></tr>');
    setHTML('ipsListedRows', '<tr><td colspan="5" class="empty-state">Not read yet</td></tr>');
    setHTML('ipsPlanRows', '<tr><td colspan="4" class="empty-state">Not previewed yet</td></tr>');
    setHTML('ipsPlanWarnings', '');
    const scr = el('ipsScript');
    if (scr) scr.style.display = 'none';
  }

  function start(): void {
    stop();
    load();
    timer = setInterval(load, POLL_MS);
  }
  function stop(): void {
    if (timer) clearInterval(timer);
    timer = null;
  }

  document.addEventListener('mikrodash:pagechange', (e) => {
    if ((e as CustomEvent).detail === 'ips') start();
    else stop();
  });
  socket.on('router:active', (d) => { if (d && d.activeId && d.activeId !== routerId) { routerId = d.activeId; clear(); load(); } });
  socket.on('router:switched', (d) => { routerId = (d && d.activeId) || ''; clear(); load(); });

  // ── tabs ─────────────────────────────────────────────────────────────────
  function showTab(key: string): void {
    tab = key;
    for (const k of ['flows', 'apps', 'events', 'rules', 'setup']) {
      const p = el('ipsPanel-' + k);
      if (p) p.style.display = k === key ? '' : 'none';
    }
    document.querySelectorAll('#ipsTabs [data-ipstab]').forEach((b) => {
      const on = b.getAttribute('data-ipstab') === key;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    draw();
  }
  el('ipsTabs')?.addEventListener('click', (e) => {
    const key = (e.target as HTMLElement | null)?.closest?.('[data-ipstab]')?.getAttribute('data-ipstab');
    if (key) showTab(key);
  });

  el('ipsFlowFilter')?.addEventListener('input', () => {
    flowFilter = q('ipsFlowFilter');
    el('ipsFlowFilter')?.classList.toggle('active', !!flowFilter);
    if (state) drawFlows(state);
  });
  el('ipsFlowMatched')?.addEventListener('click', () => {
    matchedOnly = !matchedOnly;
    el('ipsFlowMatched')?.classList.toggle('is-on', matchedOnly);
    if (state) drawFlows(state);
  });

  // ── the lists on the router ──────────────────────────────────────────────
  let listed: Listed[] = [];
  function drawListed(): void {
    renderSortHeader('ipsListedHead', [
      { key: 'list', label: 'List' }, { key: 'address', label: 'Address' }, { key: 'timeout', label: 'Times out in' },
      { key: 'comment', label: 'Why' }, { label: '' },
    ], listedSort, drawListed);
    const admin = !!state?.admin;
    const sorted = sortRows(listed, listedSort.col, listedSort.dir);
    setHTML('ipsListedRows', sorted.length ? sorted.map((x) => '<tr>' +
      '<td>' + pill(x.list.replace('mikrodash-ips-', ''), x.list.indexOf('quarantine') !== -1 ? 'warn' : 'err') + '</td>' +
      '<td>' + esc(x.address) + '</td><td>' + esc(x.timeout || '-') + '</td><td>' + esc(x.comment) + '</td>' +
      '<td class="text-end">' + (admin ? '<button class="sbtn sbtn-outline" type="button" data-ipsunlist="' +
        esc(x.list) + '|' + esc(x.address) + '">Unlist</button>' : '') + '</td></tr>').join('')
      : '<tr><td colspan="5" class="empty-state">Both lists are empty</td></tr>');
  }
  function loadListed(): void {
    setHTML('ipsListedRows', '<tr><td colspan="5" class="empty-state">Reading…</td></tr>');
    call<{ entries: Listed[] }>('/api/ips/listed' + qs())
      .then((d) => { listed = d.entries; drawListed(); })
      .catch((e: Error) => setHTML('ipsListedRows', '<tr><td colspan="5" class="empty-state">' + esc(e.message) + '</td></tr>'));
  }
  el('ipsListedLoad')?.addEventListener('click', loadListed);
  el('ipsListedRows')?.addEventListener('click', (e) => {
    const v = (e.target as HTMLElement | null)?.closest?.('[data-ipsunlist]')?.getAttribute('data-ipsunlist');
    if (!v) return;
    const [list, address] = v.split('|');
    post('/api/ips/unlist' + qs(), { list, address }).then(loadListed).catch((err: Error) => window.alert(err.message));
  });

  // ── rules ────────────────────────────────────────────────────────────────
  function showEditor(on: boolean, r?: Rule): void {
    const form = el('ipsRuleForm');
    if (form) form.style.display = on ? '' : 'none';
    editing = on ? (r || { id: 0, name: '', enabled: true, apps: [], categories: [], breeds: [], risks: [], hosts: [],
      clients: [], action: 'log', timeoutMin: 0 }) : null;
    setText('ipsRuleMsg', '');
    if (!editing) { if (state) drawRules(state); return; }
    const e = editing;
    setText('ipsRuleFormTitle', e.id ? 'Edit rule ' + e.name : 'New rule');
    const set = (id: string, v: string): void => { const n = el<HTMLInputElement>(id); if (n) n.value = v; };
    set('ipsRuleName', e.name);
    set('ipsRuleAction', e.action);
    set('ipsRuleApps', e.apps.join(', '));
    set('ipsRuleCategories', e.categories.join(', '));
    set('ipsRuleBreeds', e.breeds.join(', '));
    set('ipsRuleRisks', e.risks.join(', '));
    set('ipsRuleHosts', e.hosts.join(', '));
    set('ipsRuleClients', e.clients.join(', '));
    set('ipsRuleTimeout', e.timeoutMin ? String(e.timeoutMin) : '');
    const en = el<HTMLInputElement>('ipsRuleEnabled');
    if (en) en.checked = e.enabled;
    if (state) drawRules(state);
  }
  el('ipsRuleAdd')?.addEventListener('click', () => showEditor(true));
  el('ipsRuleCancel')?.addEventListener('click', () => showEditor(false));
  el('ipsRuleForm')?.addEventListener('submit', (ev) => {
    ev.preventDefault();
    if (!editing) return;
    const rule: Rule = {
      id: editing.id, name: q('ipsRuleName'), action: q('ipsRuleAction'),
      enabled: !!el<HTMLInputElement>('ipsRuleEnabled')?.checked,
      apps: splitList(q('ipsRuleApps')), categories: splitList(q('ipsRuleCategories')),
      breeds: splitList(q('ipsRuleBreeds')), risks: splitList(q('ipsRuleRisks')),
      hosts: splitList(q('ipsRuleHosts')), clients: splitList(q('ipsRuleClients')),
      timeoutMin: Number(q('ipsRuleTimeout')) || 0,
    };
    setText('ipsRuleMsg', 'Saving…');
    post('/api/ips/rules', rule).then(() => { showEditor(false); load(); })
      .catch((e: Error) => setText('ipsRuleMsg', e.message));
  });
  el('ipsRulesRows')?.addEventListener('click', (ev) => {
    const t = ev.target as HTMLElement | null;
    if (!state) return;
    const rules = state.rules;
    const editId = Number(t?.closest?.('[data-ipsedit]')?.getAttribute('data-ipsedit'));
    if (editId) { showEditor(true, rules.find((r) => r.id === editId)); return; }
    const delId = Number(t?.closest?.('[data-ipsdel]')?.getAttribute('data-ipsdel'));
    if (delId) {
      const r = rules.find((x) => x.id === delId);
      if (!r || !window.confirm('Delete the rule ' + r.name + '? What it listed times out on the routers.')) return;
      call('/api/ips/rules?id=' + delId, { method: 'DELETE' }).then(load).catch((e: Error) => window.alert(e.message));
      return;
    }
    const mv = t?.closest?.('[data-ipsmove]');
    if (mv) {
      const id = Number(mv.getAttribute('data-ipsmove'));
      const dir = Number(mv.getAttribute('data-dir'));
      const ids = rules.map((r) => r.id);
      const i = ids.indexOf(id);
      const j = i + dir;
      if (i < 0 || j < 0 || j >= ids.length) return;
      [ids[i], ids[j]] = [ids[j]!, ids[i]!];
      post('/api/ips/rules/order', { ids }).then(load).catch((e: Error) => window.alert(e.message));
    }
  });

  // ── setup ────────────────────────────────────────────────────────────────
  function saveSensor(newToken: boolean): void {
    setText('ipsSensorMsg', 'Saving…');
    post('/api/ips/sensor' + qs(), {
      address: q('ipsSensorAddress'), enforce: !!el<HTMLInputElement>('ipsSensorEnforce')?.checked,
      sniffBytes: Number(q('ipsSensorBytes')) || 0, protected: splitList(q('ipsSensorProtected')),
      disk: q('ipsSensorDisk'), image: q('ipsSensorImage'), newToken,
    }).then(() => {
      setText('ipsSensorMsg', newToken ? 'Saved with a new token: run the container commands again.' : 'Saved.');
      formFilledFor = '';
      load();
    }).catch((e: Error) => setText('ipsSensorMsg', e.message));
  }
  el('ipsSensorForm')?.addEventListener('submit', (ev) => { ev.preventDefault(); saveSensor(false); });
  el('ipsSensorToken')?.addEventListener('click', () => {
    if (window.confirm('Make a new token? The running sensor keeps the old one until its container is recreated.')) saveSensor(true);
  });
  el('ipsSensorDelete')?.addEventListener('click', () => {
    if (!window.confirm('Forget this router\'s sensor? Remove its rules from the router first, or they stay there.')) return;
    call('/api/ips/sensor' + qs(), { method: 'DELETE' })
      .then(() => { formFilledFor = ''; setText('ipsSensorMsg', 'Forgotten.'); load(); })
      .catch((e: Error) => setText('ipsSensorMsg', e.message));
  });

  el('ipsScriptShow')?.addEventListener('click', () => {
    call<{ script: string }>('/api/ips/script' + qs()).then((d) => {
      const pre = el('ipsScript');
      if (pre) { pre.textContent = d.script; pre.style.display = ''; }
      el('ipsScriptCopy')?.removeAttribute('disabled');
    }).catch((e: Error) => setText('ipsSensorMsg', e.message));
  });
  el('ipsScriptCopy')?.addEventListener('click', () => {
    copyText(el('ipsScript')?.textContent || '', (ok) => setText('ipsSensorMsg', ok ? 'Copied.' : 'Could not copy.'));
  });

  function drawPlan(steps: Step[], warnings: string[], done: boolean): void {
    setHTML('ipsPlanWarnings', warnings.map((w) => '<div class="muted-note mb-2">' + pill('fasttrack', 'warn') + ' ' + esc(w) + '</div>').join(''));
    setHTML('ipsPlanRows', steps.length ? steps.map((s) => '<tr><td>' + pill(s.op, s.op === 'remove' ? 'err' : s.op === 'add' ? 'ok' : 'rx') +
      '</td><td>' + esc(s.menu) + '</td><td>' + esc(s.what) + '</td><td>' +
      (!done ? '-' : s.error ? pill('failed', 'err') + ' ' + esc(s.error) : pill('done', 'ok')) + '</td></tr>').join('')
      : '<tr><td colspan="4" class="empty-state">The router already holds what it needs</td></tr>');
  }
  el('ipsPlanShow')?.addEventListener('click', () => {
    setText('ipsPlanMsg', 'Reading the firewall…');
    call<{ steps: Step[]; warnings: string[] }>('/api/ips/plan' + qs())
      .then((p) => { setText('ipsPlanMsg', ''); drawPlan(p.steps, p.warnings, false); })
      .catch((e: Error) => setText('ipsPlanMsg', e.message));
  });
  function apply(remove: boolean): void {
    const ask = remove
      ? 'Remove the IPS\'s rules from the router, and empty its two lists?'
      : 'Write the IPS\'s rules to the router? One mangle rule and three raw rules, each commented "MikroDash IPS".';
    if (!window.confirm(ask)) return;
    setText('ipsPlanMsg', 'Writing…');
    post<{ ok: boolean; steps: Step[]; warnings: string[]; cleared: number }>('/api/ips/apply' + qs() + (remove ? '&remove=1' : ''))
      .then((r) => {
        setText('ipsPlanMsg', r.ok ? (remove ? 'Removed' + (r.cleared ? ', ' + r.cleared + ' entries unlisted.' : '.') : 'Applied.')
          : 'Stopped at a failed step: preview again to see what is left.');
        drawPlan(r.steps, r.warnings, true);
      })
      .catch((e: Error) => setText('ipsPlanMsg', e.message));
  }
  el('ipsApply')?.addEventListener('click', () => apply(false));
  el('ipsRemove')?.addEventListener('click', () => apply(true));
}
