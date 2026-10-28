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

import { el, esc, pill, protoPill, renderSortHeader, sortRows, copyText, iso2Flag, type SortState } from '../dom';
import type { PillTone } from '../palette';
import type { Socket } from '../socket';
import { fmtTime } from '../timefmt';

const POLL_MS = 3000;

interface Flow {
  ts: number; l4: string; client: string; clientPort: number; server: string; serverPort: number;
  name: string; app: string; master: string; category: string; breed: string; host: string;
  risks: string[]; guessed: boolean; packets: number; bytes: number; clientCountry: string; serverCountry: string;
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
  risks: string[]; hosts: string[]; clients: string[]; countries: string[]; action: string; timeoutMin: number;
}
interface Event {
  id: number; ts: number; ruleName: string; action: string; result: string; target: string;
  client: string; server: string; serverPort: number; l4: string; app: string; host: string;
  /** The same decision again within ten minutes counts here, not as a row. */
  hits: number;
}
interface Sensor {
  address: string; enforce: boolean; sniffBytes: number; protected: string[]; disk: string; image: string;
  network: string; dhcp: boolean; everyPacket: boolean;
}
/** What nDPI can name (GET /api/ips/catalog), printed from the sensor's own nDPI. */
export interface Catalog {
  ndpi: string;
  apps: { name: string; category: string; breed: string }[];
  categories: string[]; breeds: string[]; risks: { name: string; severity: string }[];
  /** The geo database's countries; empty when this install has none. */
  countries: { iso: string; name: string }[];
}

/** The four criteria picked from lists rather than typed. */
export type PickField = 'apps' | 'categories' | 'breeds' | 'risks' | 'countries';

/**
 * A pick box: the values chosen, each a chip that removes itself, then a list
 * of what is left to add. Applications come grouped by their nDPI category; a
 * value a rule already holds that the catalogue does not name still shows, so
 * an older rule is never silently emptied.
 */
export function pickHtml(field: PickField, chosen: string[], cat: Catalog | null): string {
  const label = (v: string): string => v === '*' && field === 'risks' ? 'Any risk'
    : field === 'countries' ? (iso2Flag(v) + ' ' + v).trim() : v;
  const chips = chosen.map((v) => '<span class="chip is-on">' + esc(label(v)) +
    '<button class="chip-x" type="button" title="Remove" data-ipsunpick="' + esc(field) + '" data-v="' + esc(v) + '">×</button></span>').join(' ');
  const left = (list: string[]): string[] => list.filter((v) => !chosen.includes(v));
  const opt = (v: string, label = v): string => '<option value="' + esc(v) + '">' + esc(label) + '</option>';
  const prompt: Record<PickField, string> = { apps: 'Add an application', categories: 'Add a category',
    breeds: 'Add a breed', risks: 'Add a risk', countries: 'Add a country' };
  let options = '';
  if (cat) {
    if (field === 'apps') {
      const groups: Record<string, string[]> = {};
      for (const a of cat.apps) if (!chosen.includes(a.name)) (groups[a.category] ||= []).push(a.name);
      options = Object.keys(groups).sort().map((g) => '<optgroup label="' + esc(g) + '">' +
        groups[g]!.sort((x, y) => x.localeCompare(y)).map((v) => opt(v)).join('') + '</optgroup>').join('');
    } else if (field === 'risks') {
      options = (chosen.includes('*') ? '' : opt('*', 'Any risk')) +
        cat.risks.filter((r) => !chosen.includes(r.name)).map((r) => opt(r.name, r.name + ' (' + r.severity + ')')).join('');
    } else if (field === 'countries') {
      options = cat.countries.filter((c) => !chosen.includes(c.iso)).map((c) => opt(c.iso, c.name + ' (' + c.iso + ')')).join('');
    } else {
      options = left(field === 'categories' ? cat.categories : cat.breeds).map((v) => opt(v)).join('');
    }
  }
  const none = field === 'countries' && cat && !cat.countries.length;
  return chips + (chips ? ' ' : '') + '<select class="sform-input sform-sm" data-ipsadd="' + esc(field) + '"' +
    (cat && !none ? '' : ' disabled') + '><option value="">' +
    (!cat ? 'Loading the list' : none ? 'No geo database on this install' : prompt[field]) + '</option>' +
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
/** GET /api/ips/geo: the router's country lists, and the apply writing them. */
export interface GeoJob { running: boolean; remove: boolean; phase: string; done: number; total: number; error: string; conflicts: string[] }
export interface GeoState {
  geo: { mode: string; countries: string[]; allow: string[]; direction: string; appliedAt: number; result: string;
    entries: number; saved: boolean };
  job: GeoJob; available: boolean; list: string; allowList: string; maxEntries: number; routerCountry: string;
}

/** What Apply or Remove asks before writing: what will be dropped, in which direction. */
export function geoApplyQuestion(remove: boolean, mode: string, dir: string, allow: string[], block: string[]): string {
  const way = ({ in: 'from', out: 'to', both: 'to and from' } as Record<string, string>)[dir] || 'to and from';
  const dropped = block.filter((c) => !allow.includes(c));
  if (remove || (mode !== 'allow' && !dropped.length)) {
    return 'Remove the geofencing rules from the router, and empty its geofencing lists?';
  }
  if (mode === 'allow') {
    return 'Drop new connections ' + way + ' every country but ' + allow.join(', ') +
      ' (private addresses stay allowed)? Check that every place you reach the router from is on the whitelist.';
  }
  return 'Drop new connections ' + way + ' ' + dropped.join(', ') + '?' +
    (dropped.length < block.length ? ' (' + block.filter((c) => allow.includes(c)).join(', ') + ' stays: whitelisted.)' : '');
}

const INSPECT_FIRST_HELP = 'nDPI names a connection from its first packets; the rest costs the router without naming more.';

/** What the Setup screen says when every packet is chosen. */
export const INSPECT_ALL_WARNING = 'Warning: every packet of every connection is copied to the sensor. The router sends ' +
  'its whole forwarded throughput a second time and the sensor inspects all of it: only for a router sized for it ' +
  '(a CCR or an RB5009 with CPU to spare, a fast link to the sensor). Watch its CPU after applying and go back to the ' +
  'first bytes if it climbs. A fasttrack rule must be disabled, or fasttracked connections stop being inspected.';

/** GET /api/ips/sensor/update: the sensor's release, the registry's newest, the update job. */
export interface SensorUpdate {
  image: string; running: string; newest: string; available: boolean; checkedAt: number; checkError: string;
  job: { running: boolean; phase: string; error: string; from: string; to: string; at: number };
}

/** The Setup tab's line about the sensor's release. */
export function updateNote(u: SensorUpdate): string {
  const running = u.running ? 'The sensor runs ' + u.running + '.' : 'The sensor does not report its release (before 0.2.0).';
  if (u.checkError) return running + ' The registry could not be read: ' + u.checkError;
  if (!u.newest) return running + (u.checkedAt ? ' The registry has no release yet.' : ' Checking the registry…');
  return running + (u.available ? ' ' + u.newest + ' is available.' : ' It is the newest (' + u.newest + ').');
}

/** The update job, as its line reads. */
export function updateJobLine(u: SensorUpdate): string {
  const j = u.job;
  if (j.running) return 'Updating to ' + j.to + ': ' + j.phase + '…';
  if (j.error) return 'The update to ' + j.to + ' stopped: ' + j.error;
  if (j.at && j.phase === 'done') return 'Updated to ' + j.to + '.';
  return '';
}

/** A geofencing apply as its line reads: the phase, how far, and how it ended. */
export function geoJobLine(j: GeoJob): string {
  if (j.running) return (j.remove ? 'Removing: ' : 'Applying: ') + j.phase + (j.total ? ' ' + j.done + ' / ' + j.total : '') + '…';
  if (j.error) return 'Stopped: ' + j.error + (j.conflicts.length ? ' (' + j.conflicts.join(', ') + ')' : '');
  return '';
}
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

/** An address with its country's flag before it, the code in the title. */
export function flagged(addr: string, country: string): string {
  return country ? '<span title="' + esc(country) + '">' + iso2Flag(country) + '</span> ' + esc(addr) : esc(addr);
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
    breeds: [], risks: [], hosts: named ? [] : [host], clients: [], countries: [], action: 'block', timeoutMin: 60 };
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
  add('country', r.countries);
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
  const picks: Record<PickField, string[]> = { apps: [], categories: [], breeds: [], risks: [], countries: [] };
  let chosenNetwork = '';
  let geo: GeoState | null = null;
  let upd: SensorUpdate | null = null;
  let updAsked = 0;
  let geoFor = '';
  // The whitelist and the blacklist as the form holds them.
  const geoPicks: Record<'allow' | 'block', string[]> = { allow: [], block: [] };
  const flowSort: SortState = { col: 'ts', dir: 'desc' };
  const appSort: SortState = { col: 'flows', dir: 'desc' };
  const eventSort: SortState = { col: 'ts', dir: 'desc' };
  const riskSort: SortState = { col: 'rank', dir: 'desc' };
  const listedSort: SortState = { col: 'address', dir: 'asc' };

  const setText = (id: string, t: string): void => { const n = el(id); if (n) n.textContent = t; };
  const setHTML = (id: string, h: string): void => { const n = el(id); if (n) n.innerHTML = h; };
  const q = (id: string): string => (el<HTMLInputElement>(id)?.value || '').trim();
  const qs = (): string => '?router=' + encodeURIComponent(routerId);

  // The release is asked every 30 s, or at every poll while an update runs
  // or the Setup tab is open; the server answers from its cache.
  function loadUpdate(check = false): void {
    if (!routerId) return;
    const asked = routerId;
    updAsked = Date.now();
    call<SensorUpdate>('/api/ips/sensor/update' + qs() + (check ? '&check=1' : ''))
      .then((u) => { if (asked === routerId) { upd = u; drawUpdate(); } })
      .catch(() => { /* the page goes on without it */ });
  }
  function drawUpdate(): void {
    const u = upd;
    const admin = !!state?.admin;
    setHTML('ipsUpdatePill', u && u.available ? pill('update ' + u.newest, 'warn') : '');
    if (!u || !u.job) return;
    setText('ipsUpdateNote', updateNote(u));
    setText('ipsUpdateJob', updateJobLine(u));
    const b = el('ipsUpdateBtn');
    if (b) {
      b.style.display = admin && (u.available || u.job.running) ? '' : 'none';
      b.textContent = 'Update the sensor to ' + u.newest;
      b.toggleAttribute('disabled', u.job.running);
    }
    const c = el('ipsUpdateCheck');
    if (c) c.style.display = admin ? '' : 'none';
  }

  function load(): void {
    if (!routerId || !isVisible('ips')) return;
    if (upd?.job?.running || tab === 'setup' || Date.now() - updAsked > 30000) loadUpdate();
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
      '<td>' + flagged(x.client, x.clientCountry) + '</td>' +
      '<td>' + flagged(x.server, x.serverCountry) + ':' + x.serverPort + '</td>' +
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
      { key: 'client', label: 'Flow' }, { key: 'hits', label: 'Times' },
    ], eventSort, () => drawEvents(s));
    const sorted = sortRows(s.events, eventSort.col, eventSort.dir);
    setHTML('ipsEventsRows', sorted.length ? sorted.map((e) => '<tr>' +
      '<td>' + esc(fmtTime(e.ts)) + '</td><td>' + esc(e.ruleName) + '</td>' +
      '<td>' + pill(e.action, ACTION_TONE[e.action] || 'muted') + '</td>' +
      '<td>' + pill(e.result, resultTone(e.result)) + '</td>' +
      '<td>' + esc(e.target || '-') + '</td><td>' + esc(e.app) + (e.host ? ' <span class="muted-note">' + esc(e.host) + '</span>' : '') + '</td>' +
      '<td>' + esc(e.client) + ' → ' + esc(e.server) + ':' + e.serverPort + '</td>' +
      '<td>' + (e.hits > 1 ? '×' + e.hits : '') + '</td></tr>').join('')
      : '<tr><td colspan="8" class="empty-state">No decisions yet</td></tr>');
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
    set('ipsSensorInspect', sn?.everyPacket ? 'all' : 'first');
    syncInspect();
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

  // EVERY PACKET has no byte count to set, and says what it costs.
  function syncInspect(): void {
    const all = el<HTMLSelectElement>('ipsSensorInspect')?.value === 'all';
    const bytes = el('ipsSensorBytesField');
    if (bytes) bytes.style.display = all ? 'none' : '';
    const help = el('ipsSensorInspectHelp');
    if (help) {
      help.textContent = all ? INSPECT_ALL_WARNING : INSPECT_FIRST_HELP;
      help.style.color = all ? 'var(--accent-warn)' : '';
    }
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
    if (tab === 'geo' && geo?.job.running) loadGeo();
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
    geo = null;
    geoFor = '';
    if (tab === 'geo') loadGeo();
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
    for (const k of ['flows', 'apps', 'risks', 'events', 'rules', 'geo', 'setup']) {
      const p = el('ipsPanel-' + k);
      if (p) p.style.display = k === key ? '' : 'none';
    }
    document.querySelectorAll('#ipsTabs [data-ipstab]').forEach((b) => {
      const on = b.getAttribute('data-ipstab') === key;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    if (key === 'geo') loadGeo();
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
    breeds: 'ipsRuleBreedsPick', risks: 'ipsRuleRisksPick', countries: 'ipsRuleCountriesPick' };
  function drawPicks(): void {
    for (const f of Object.keys(PICK_IDS) as PickField[]) setHTML(PICK_IDS[f], pickHtml(f, picks[f], catalog));
  }
  // ONCE PER PAGE: the catalogue is the sensor's nDPI and does not change while
  // MikroDash runs.
  function loadCatalog(): void {
    if (catalogAsked) return;
    catalogAsked = true;
    call<Catalog>('/api/ips/catalog').then((c) => { catalog = c; drawPicks(); drawGeoPick(); })
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
      clients: [], countries: [], action: 'log', timeoutMin: 0 }) : null;
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
    picks.countries = [...(e.countries || [])];
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
      breeds: [...picks.breeds], risks: [...picks.risks], countries: [...picks.countries],
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
      everyPacket: el<HTMLSelectElement>('ipsSensorInspect')?.value === 'all',
    }).then(() => {
      setText('ipsSensorMsg', newToken ? 'Saved with a new token: run the container commands again.' : 'Saved.');
      formFilledFor = '';
      load();
    }).catch((e: Error) => setText('ipsSensorMsg', e.message));
  }
  el('ipsSensorForm')?.addEventListener('submit', (ev) => { ev.preventDefault(); saveSensor(false); });
  el('ipsSensorDhcp')?.addEventListener('change', syncDhcp);
  el('ipsSensorInspect')?.addEventListener('change', syncInspect);
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
      : 'Write the IPS\'s rules to the router? One mangle rule and three raw rules, each commented "MikroDash IPS".' +
        (state?.sensor?.everyPacket ? '\n\nEVERY PACKET is copied to the sensor: the router sends its whole forwarded ' +
          'throughput a second time. Only for a router sized for it.' : '');
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
  el('ipsUpdatePill')?.addEventListener('click', () => showTab('setup'));
  el('ipsUpdateCheck')?.addEventListener('click', () => loadUpdate(true));
  el('ipsUpdateBtn')?.addEventListener('click', () => {
    if (!upd) return;
    if (!window.confirm('Update the sensor to ' + upd.newest + '? The router re-pulls ' + upd.image +
      ' and restarts the container: nothing is inspected for a minute or two.')) return;
    post('/api/ips/sensor/update' + qs()).then(() => loadUpdate()).catch((e: Error) => setText('ipsUpdateJob', e.message));
  });
  el('ipsApply')?.addEventListener('click', () => apply(false));
  el('ipsRemove')?.addEventListener('click', () => apply(true));

  // ── geofencing ───────────────────────────────────────────────────────────
  // The choice is saved, then applied: an apply is a job on the server, and
  // its progress rides the page's poll while it runs.
  function drawGeoPick(): void {
    setHTML('ipsGeoAllowPick', pickHtml('countries', geoPicks.allow, catalog));
    setHTML('ipsGeoBlockPick', pickHtml('countries', geoPicks.block, catalog));
    syncGeoMode();
  }
  // ALLOW ONLY THE WHITELIST makes the blacklist moot: its field goes.
  function syncGeoMode(): void {
    const allow = el<HTMLSelectElement>('ipsGeoMode')?.value === 'allow';
    const f = el('ipsGeoBlockField');
    if (f) f.style.display = allow ? 'none' : '';
    setText('ipsGeoModeHelp', allow
      ? 'Drops new connections from (or to) every country but the whitelist\'s. Private addresses are always allowed.'
      : 'Drops new connections from (or to) the blacklist\'s countries.');
  }
  function drawGeo(): void {
    const admin = !!state?.admin;
    const g = geo;
    for (const id of ['ipsGeoForm', 'ipsGeoActions']) {
      const n = el(id);
      if (n) n.style.display = admin ? '' : 'none';
    }
    if (!g) { setText('ipsGeoNote', 'Reading…'); return; }
    setText('ipsGeoNote', !g.available ? 'Geofencing needs the DB-IP geo database, which this install does not have.'
      : admin ? 'Drop new connections to or from whole countries, on the router itself: no sensor needed.'
        : 'Geofencing is configured by administrators.');
    setText('ipsGeoListNote', 'The list ' + (g.geo.mode === 'allow' ? g.allowList : g.list) + ', at most ' + g.maxEntries +
      ' networks, and two or three filter rules commented "MikroDash IPS: geo". Apply again after a geo database update: ' +
      'only the difference is written.');
    setText('ipsGeoAllowHelp', 'Never dropped.' + (g.routerCountry ? ' The router is in ' + g.routerCountry +
      (g.geo.saved ? '.' : ', so it is on the whitelist until you save another choice.') : ''));
    const running = g.job.running;
    for (const id of ['ipsGeoApply', 'ipsGeoRemove']) el(id)?.toggleAttribute('disabled', running || !g.available);
    setText('ipsGeoJob', geoJobLine(g.job));
    setText('ipsGeoLast', g.geo.appliedAt ? 'Last: ' + g.geo.result + ', ' + g.geo.entries + ' networks listed, ' +
      fmtTime(g.geo.appliedAt) + '.' : 'Never applied to this router.');
  }
  function loadGeo(): void {
    if (!routerId) return;
    const asked = routerId;
    loadCatalog();
    call<GeoState>('/api/ips/geo' + qs()).then((g) => {
      if (asked !== routerId) return;
      geo = g;
      if (geoFor !== asked) {
        geoFor = asked;
        geoPicks.allow = [...g.geo.allow];
        geoPicks.block = [...g.geo.countries];
        const d = el<HTMLSelectElement>('ipsGeoDirection');
        if (d) d.value = g.geo.direction;
        const m = el<HTMLSelectElement>('ipsGeoMode');
        if (m) m.value = g.geo.mode || 'block';
        drawGeoPick();
      }
      drawGeo();
    }).catch((e: Error) => setText('ipsGeoNote', e.message));
  }
  // Which list a pick box edits: its box's data-geolist.
  const geoListOf = (n: Element | null): 'allow' | 'block' =>
    n?.closest?.('[data-geolist]')?.getAttribute('data-geolist') === 'allow' ? 'allow' : 'block';
  el('ipsGeoForm')?.addEventListener('change', (ev) => {
    const t = ev.target as HTMLElement | null;
    if (t?.id === 'ipsGeoMode') { syncGeoMode(); return; }
    const sel = t?.closest?.('[data-ipsadd]') as HTMLSelectElement | null;
    if (!sel || !sel.value) return;
    const list = geoPicks[geoListOf(sel)];
    if (!list.includes(sel.value)) list.push(sel.value);
    drawGeoPick();
  });
  el('ipsGeoForm')?.addEventListener('click', (ev) => {
    const b = (ev.target as HTMLElement | null)?.closest?.('[data-ipsunpick]');
    if (!b) return;
    const which = geoListOf(b);
    geoPicks[which] = geoPicks[which].filter((v) => v !== b.getAttribute('data-v'));
    drawGeoPick();
  });
  function saveGeo(): Promise<void> {
    return post<{ countries: string[]; allow: string[] }>('/api/ips/geo' + qs(), {
      mode: el<HTMLSelectElement>('ipsGeoMode')?.value || 'block', countries: geoPicks.block, allow: geoPicks.allow,
      direction: el<HTMLSelectElement>('ipsGeoDirection')?.value || 'both' })
      .then((r) => { geoPicks.block = r.countries; geoPicks.allow = r.allow; drawGeoPick(); });
  }
  el('ipsGeoForm')?.addEventListener('submit', (ev) => {
    ev.preventDefault();
    setText('ipsGeoMsg', 'Saving…');
    saveGeo().then(() => { setText('ipsGeoMsg', 'Saved. Apply it to the router to take effect.'); loadGeo(); })
      .catch((e: Error) => setText('ipsGeoMsg', e.message));
  });
  // APPLY SAVES FIRST: what is written is what the form shows.
  function applyGeo(remove: boolean): void {
    const dir = el<HTMLSelectElement>('ipsGeoDirection')?.value || 'both';
    const ask = geoApplyQuestion(remove, el<HTMLSelectElement>('ipsGeoMode')?.value || 'block', dir, geoPicks.allow, geoPicks.block);
    if (!window.confirm(ask)) return;
    (remove ? Promise.resolve() : saveGeo())
      .then(() => post('/api/ips/geo/apply' + qs() + (remove ? '&remove=1' : '')))
      .then(loadGeo)
      .catch((e: Error) => setText('ipsGeoJob', e.message));
  }
  el('ipsGeoApply')?.addEventListener('click', () => applyGeo(false));
  el('ipsGeoRemove')?.addEventListener('click', () => applyGeo(true));
}
