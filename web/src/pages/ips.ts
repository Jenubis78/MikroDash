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
  action: string; rule: string; result: string; severity: string;
}
interface RiskCount {
  name: string; severity: string; flows: number; clients: number; apps: string[];
  lastTs: number; lastClient: string; lastServer: string;
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
  network: string; dhcp: boolean;
}
/** What nDPI can name (GET /api/ips/catalog), printed from the sensor's own nDPI. */
export interface Catalog {
  ndpi: string;
  apps: { name: string; category: string; breed: string }[];
  categories: string[]; breeds: string[]; risks: string[];
}

/** The four criteria picked from lists rather than typed. */
export type PickField = 'apps' | 'categories' | 'breeds' | 'risks';

/**
 * A pick box: the values chosen, each a chip that removes itself, then a list
 * of what is left to add. Applications come grouped by their nDPI category; a
 * value a rule already holds that the catalogue does not name still shows, so
 * an older rule is never silently emptied.
 */
export function pickHtml(field: PickField, chosen: string[], cat: Catalog | null): string {
  const chips = chosen.map((v) => '<span class="chip is-on">' + esc(v === '*' ? 'Any risk' : v) +
    '<button class="chip-x" type="button" title="Remove" data-ipsunpick="' + esc(field) + '" data-v="' + esc(v) + '">×</button></span>').join(' ');
  const left = (list: string[]): string[] => list.filter((v) => !chosen.includes(v));
  const opt = (v: string, label = v): string => '<option value="' + esc(v) + '">' + esc(label) + '</option>';
  const prompt: Record<PickField, string> = { apps: 'Add an application', categories: 'Add a category',
    breeds: 'Add a breed', risks: 'Add a risk' };
  let options = '';
  if (cat) {
    if (field === 'apps') {
      const groups: Record<string, string[]> = {};
      for (const a of cat.apps) if (!chosen.includes(a.name)) (groups[a.category] ||= []).push(a.name);
      options = Object.keys(groups).sort().map((g) => '<optgroup label="' + esc(g) + '">' +
        groups[g]!.sort((x, y) => x.localeCompare(y)).map((v) => opt(v)).join('') + '</optgroup>').join('');
    } else if (field === 'risks') {
      options = (chosen.includes('*') ? '' : opt('*', 'Any risk')) + left(cat.risks).map((v) => opt(v)).join('');
    } else {
      options = left(field === 'categories' ? cat.categories : cat.breeds).map((v) => opt(v)).join('');
    }
  }
  return chips + (chips ? ' ' : '') + '<select class="sform-input sform-sm" data-ipsadd="' + esc(field) + '"' +
    (cat ? '' : ' disabled') + '><option value="">' + (cat ? prompt[field] : 'Loading the list') + '</option>' +
    options + '</select>';
}

/** One of the router's networks, as GET /api/ips/networks lists it. */
export interface Network { interface: string; prefix: string; gateway: string; bridge: string; vlan: number; why: string }

/** A network as its option reads: the interface, the subnet, and the VLAN when there is one. */
export function networkLabel(n: Network): string {
  return n.interface + ' - ' + n.prefix + (n.vlan ? ' (VLAN ' + n.vlan + ' on ' + n.bridge + ')' : '') +
    // A greyed option cannot be picked, so its help line never shows: the
    // reason rides in the label itself.
    (n.why ? ' - cannot be joined: ' + n.why : '');
}
interface State {
  configured: boolean; sensor: Sensor | null; status: Status; flows: Flow[]; apps: AppCount[]; risks: RiskCount[];
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

/** One flow's identity: its start and its five-tuple. */
export function flowKey(f: Flow): string {
  return f.ts + '|' + f.l4 + '|' + f.client + '|' + f.clientPort + '|' + f.server + '|' + f.serverPort;
}

/** nDPI's severities, least first: a rank to sort by, 0 for none. */
export function severityRank(s: string): number {
  return ['Low', 'Medium', 'High', 'Severe', 'Critical', 'Emergency'].indexOf(s) + 1;
}

/** The tone of a severity: blue for low, amber for medium, red from high up. */
export function severityTone(s: string): PillTone {
  const r = severityRank(s);
  return r >= 3 ? 'err' : r === 2 ? 'warn' : r === 1 ? 'rx' : 'muted';
}

/** A flow's risks as one pill: its worst severity, and how many, every name in the title. */
export function riskPill(severity: string, risks: string[]): string {
  if (!risks.length) return '-';
  const n = risks.length > 1 ? ' · ' + risks.length : '';
  return '<span title="' + esc(risks.join(', ')) + '">' + pill((severity || 'Risk') + n, severityTone(severity)) + '</span>';
}

/**
 * The rule the Block button on a flow proposes: block its application when
 * nDPI named one, else its host. Null when the flow carries neither, since a
 * rule on clients alone is refused.
 */
export function blockRuleFor(f: Flow): Rule | null {
  const named = f.app && f.app !== 'Unknown' ? f.app : '';
  const host = f.host ? f.host.replace(/^www\./, '') : '';
  if (!named && !host) return null;
  const what = named || host;
  return { id: 0, name: ('Block ' + what).slice(0, 60), enabled: true, apps: named ? [named] : [], categories: [],
    breeds: [], risks: [], hosts: named ? [] : [host], clients: [], action: 'block', timeoutMin: 60 };
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
  let riskyOnly = false;
  // PAUSED, the Flows table keeps the window it had; flows still arrive.
  let frozen: Flow[] | null = null;
  let editing: Rule | null = null;
  let formFilledFor = '';
  let networks: Network[] = [];
  let networksFor = '';
  let networksError = '';
  let catalog: Catalog | null = null;
  let catalogAsked = false;
  const picks: Record<PickField, string[]> = { apps: [], categories: [], breeds: [], risks: [] };
  let chosenNetwork = '';
  const flowSort: SortState = { col: 'ts', dir: 'desc' };
  const appSort: SortState = { col: 'flows', dir: 'desc' };
  const eventSort: SortState = { col: 'ts', dir: 'desc' };
  const riskSort: SortState = { col: 'rank', dir: 'desc' };
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
    const shown = frozen || s.flows;
    const rows = shown.filter((x) => (!matchedOnly || x.action) && (!riskyOnly || x.risks.length) && (!f ||
      [x.client, x.server, x.name, x.host, x.category].some((v) => v.toLowerCase().indexOf(f) !== -1)))
      .map((x) => ({ ...x, rank: severityRank(x.severity) }));
    renderSortHeader('ipsFlowsHead', [
      { key: 'ts', label: 'Time' }, { key: 'l4', label: 'Proto' }, { key: 'client', label: 'Client' },
      { key: 'server', label: 'Server' }, { key: 'name', label: 'Application' }, { key: 'rank', label: 'Risk' },
      { key: 'category', label: 'Category' }, { key: 'host', label: 'Host' }, { key: 'action', label: 'Decision' },
      { label: '' },
    ], flowSort, () => drawFlows(s));
    const sorted = sortRows(rows, flowSort.col, flowSort.dir);
    // The row's index in `shown` is what the Block button names: a sort or a
    // filter moves the row, never what it points at.
    setHTML('ipsFlowsRows', sorted.length ? sorted.map((x) => '<tr>' +
      '<td>' + esc(fmtTime(x.ts)) + '</td>' +
      '<td>' + protoPill(x.l4) + '</td>' +
      '<td>' + esc(x.client) + '</td>' +
      '<td>' + esc(x.server) + ':' + x.serverPort + '</td>' +
      '<td>' + pill(x.name || 'Unknown', x.guessed ? 'muted' : 'alt') + '</td>' +
      '<td>' + riskPill(x.severity, x.risks) + '</td>' +
      '<td>' + esc(x.category || '-') + '</td>' +
      '<td>' + esc(x.host || '-') + '</td>' +
      '<td>' + (x.action ? pill(x.action, ACTION_TONE[x.action] || 'muted') + ' ' + pill(x.result, resultTone(x.result)) : '-') + '</td>' +
      '<td class="text-end">' + (s.admin && blockRuleFor(x) ? '<button class="sbtn sbtn-danger" type="button" data-ipsblock="' +
        shown.findIndex((y) => flowKey(y) === flowKey(x)) +
        '" title="A rule that blocks this flow\'s application or host">Block</button>' : '') + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="10" class="empty-state">' + (shown.length ? 'No flow matches' : 'No flows yet') + '</td></tr>');
    const pause = el('ipsFlowPause');
    if (pause) {
      // BY IDENTITY, NOT BY TIME: a flow's ts is when it STARTED, and the
      // sensor reports it when nDPI is done, so a later report can carry an
      // earlier time.
      const seen = new Set((frozen || []).map(flowKey));
      const fresh = frozen ? s.flows.filter((x) => !seen.has(flowKey(x))).length : 0;
      pause.classList.toggle('is-on', !!frozen);
      pause.textContent = frozen ? 'Paused' + (fresh ? ' · ' + fresh + ' new' : '') : 'Pause';
    }
  }

  function drawRisks(s: State): void {
    renderSortHeader('ipsRisksHead', [
      { key: 'rank', label: 'Severity' }, { key: 'name', label: 'Risk' }, { key: 'flows', label: 'Flows' },
      { key: 'clients', label: 'Clients' }, { label: 'Applications' }, { key: 'lastTs', label: 'Last seen' },
      { label: 'Last flow' },
    ], riskSort, () => drawRisks(s));
    const sorted = sortRows(s.risks.map((r) => ({ ...r, rank: severityRank(r.severity) })), riskSort.col, riskSort.dir);
    setHTML('ipsRisksRows', sorted.length ? sorted.map((r) => '<tr>' +
      '<td>' + pill(r.severity || 'Unrated', severityTone(r.severity)) + '</td>' +
      '<td>' + esc(r.name) + '</td><td>' + r.flows + '</td><td>' + r.clients + '</td>' +
      '<td>' + (r.apps.length ? r.apps.map((a) => pill(a, 'alt', true)).join(' ') : '-') + '</td>' +
      '<td>' + esc(fmtTime(r.lastTs)) + '</td>' +
      '<td>' + esc(r.lastClient) + ' → ' + esc(r.lastServer) + '</td></tr>').join('')
      : '<tr><td colspan="7" class="empty-state">No risk raised yet</td></tr>');
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
    const dhcp = el<HTMLInputElement>('ipsSensorDhcp');
    if (dhcp) dhcp.checked = !!sn?.dhcp;
    chosenNetwork = sn?.network || '';
    drawNetworks();
    syncDhcp();
    const img = el<HTMLInputElement>('ipsSensorImage');
    if (img) img.placeholder = s.defaults.image;
  }

  function drawNetworks(): void {
    const sel = el<HTMLSelectElement>('ipsSensorNetwork');
    if (!sel) return;
    const keep = chosenNetwork;
    const dhcp = !!el<HTMLInputElement>('ipsSensorDhcp')?.checked;
    // By DHCP no address says which network: the first entry asks for one.
    sel.innerHTML = '<option value="">' + (dhcp ? 'Choose the network' : 'By the address') + '</option>' +
      networks.map((n) => '<option value="' + esc(n.interface) + '"' + (n.why ? ' disabled' : '') + '>' +
        esc(networkLabel(n)) + '</option>').join('') +
      (keep && !networks.some((n) => n.interface === keep) ? '<option value="' + esc(keep) + '">' + esc(keep) + '</option>' : '');
    sel.value = keep;
    sel.classList.toggle('active', dhcp && !keep);
    const n = networks.find((x) => x.interface === keep);
    let help = 'The bridge or VLAN the container joins, read from the router.';
    if (networksError) help = 'The router\'s networks could not be read: ' + networksError;
    else if (n) help = n.why || 'Joins ' + n.bridge + (n.vlan ? ' with pvid ' + n.vlan : '') + '; the router is ' + n.gateway + '.';
    else if (dhcp) help = 'By DHCP, choose the network the sensor joins.';
    else if (networksFor && !networks.length) help = 'The router has no IPv4 network to join.';
    setText('ipsSensorNetworkHelp', help);
  }

  function loadNetworks(): void {
    if (!state?.admin || !routerId || networksFor === routerId) return;
    networksFor = routerId;
    call<{ networks: Network[] }>('/api/ips/networks' + qs())
      .then((d) => { networksError = ''; networks = d.networks; drawNetworks(); })
      // SAID, NOT RETRIED EVERY POLL: the list is read again when the Setup
      // tab is opened again, and the reason stays under the field until then.
      .catch((e: Error) => { networksError = e.message; drawNetworks(); });
  }

  // BY DHCP, the address is the server's: its field goes, and a network must
  // be chosen, since no address says which one.
  function syncDhcp(): void {
    const on = !!el<HTMLInputElement>('ipsSensorDhcp')?.checked;
    const f = el('ipsSensorAddressField');
    if (f) f.style.display = on ? 'none' : '';
    drawNetworks();
  }

  function drawSetup(s: State): void {
    setText('ipsSetupNote', s.admin
      ? 'The sensor runs as a container on the router. Save it here, create the container, then apply the rules.'
      : 'The IPS is configured by administrators.');
    for (const id of ['ipsSensorForm', 'ipsScriptShow', 'ipsScriptCopy', 'ipsPlanShow', 'ipsApply', 'ipsRemove']) {
      const n = el(id);
      if (n) n.style.display = s.admin ? '' : 'none';
    }
    if (tab === 'setup') loadNetworks();
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
    if (tab === 'risks') drawRisks(s);
    if (tab === 'apps') drawApps(s);
    if (tab === 'events') drawEvents(s);
    drawRules(s);
    drawSetup(s);
  }

  function clear(): void {
    state = null;
    formFilledFor = '';
    frozen = null;
    networks = [];
    networksFor = '';
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
    if (key === 'setup' && tab !== 'setup' && networksError) networksFor = ''; // read again on return
    tab = key;
    for (const k of ['flows', 'apps', 'risks', 'events', 'rules', 'setup']) {
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
  el('ipsFlowRisky')?.addEventListener('click', () => {
    riskyOnly = !riskyOnly;
    el('ipsFlowRisky')?.classList.toggle('is-on', riskyOnly);
    if (state) drawFlows(state);
  });
  el('ipsFlowPause')?.addEventListener('click', () => {
    frozen = frozen ? null : [...(state?.flows || [])];
    if (state) drawFlows(state);
  });
  el('ipsFlowsRows')?.addEventListener('click', (ev) => {
    const b = (ev.target as HTMLElement | null)?.closest?.('[data-ipsblock]');
    if (!b) return;
    const x = (frozen || state?.flows || [])[Number(b.getAttribute('data-ipsblock'))];
    const r = x && blockRuleFor(x);
    if (!r) return;
    showTab('rules');
    showEditor(true, r);
    el('ipsRuleForm')?.scrollIntoView({ block: 'start' });
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
  const PICK_IDS: Record<PickField, string> = { apps: 'ipsRuleAppsPick', categories: 'ipsRuleCategoriesPick',
    breeds: 'ipsRuleBreedsPick', risks: 'ipsRuleRisksPick' };
  function drawPicks(): void {
    for (const f of Object.keys(PICK_IDS) as PickField[]) setHTML(PICK_IDS[f], pickHtml(f, picks[f], catalog));
  }
  // ONCE PER PAGE: the catalogue is the sensor's nDPI and does not change while
  // MikroDash runs.
  function loadCatalog(): void {
    if (catalogAsked) return;
    catalogAsked = true;
    call<Catalog>('/api/ips/catalog').then((c) => { catalog = c; drawPicks(); })
      .catch(() => { catalogAsked = false; });
  }
  el('ipsRuleForm')?.addEventListener('change', (ev) => {
    const sel = (ev.target as HTMLElement | null)?.closest?.('[data-ipsadd]') as HTMLSelectElement | null;
    if (!sel || !sel.value) return;
    const f = sel.getAttribute('data-ipsadd') as PickField;
    if (!picks[f].includes(sel.value)) picks[f].push(sel.value);
    drawPicks();
  });
  el('ipsRuleForm')?.addEventListener('click', (ev) => {
    const b = (ev.target as HTMLElement | null)?.closest?.('[data-ipsunpick]');
    if (!b) return;
    const f = b.getAttribute('data-ipsunpick') as PickField;
    picks[f] = picks[f].filter((v) => v !== b.getAttribute('data-v'));
    drawPicks();
  });

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
    picks.apps = [...e.apps];
    picks.categories = [...e.categories];
    picks.breeds = [...e.breeds];
    picks.risks = [...e.risks];
    drawPicks();
    loadCatalog();
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
      apps: [...picks.apps], categories: [...picks.categories],
      breeds: [...picks.breeds], risks: [...picks.risks],
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
      network: el<HTMLSelectElement>('ipsSensorNetwork')?.value || '', dhcp: !!el<HTMLInputElement>('ipsSensorDhcp')?.checked,
    }).then(() => {
      setText('ipsSensorMsg', newToken ? 'Saved with a new token: run the container commands again.' : 'Saved.');
      formFilledFor = '';
      load();
    }).catch((e: Error) => setText('ipsSensorMsg', e.message));
  }
  el('ipsSensorForm')?.addEventListener('submit', (ev) => { ev.preventDefault(); saveSensor(false); });
  el('ipsSensorDhcp')?.addEventListener('change', syncDhcp);
  el('ipsSensorNetwork')?.addEventListener('change', () => {
    chosenNetwork = el<HTMLSelectElement>('ipsSensorNetwork')?.value || '';
    drawNetworks();
  });
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
