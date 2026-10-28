// The Traffic Analysis page (2026-10-28): the routers' IPFIX, named by the
// IPS sensor's nDPI, by application, category, host and country.
//
// ── ASKED FOR WHILE SHOWN ───────────────────────────────────────────────────
//
// The collector runs on the server whether or not anybody looks
// (internal/server/traffic.go). This page asks /api/traffic/state every
// POLL_MS while it is the page shown; History and Flows are read when their
// tab is opened or a filter changes. Nothing here writes to the router except
// the Setup tab's Apply and Remove, each confirmed.
//
// ── RATES ARE A SPAN'S BYTES ────────────────────────────────────────────────
//
// Traffic Flow exports once a minute, so Live is the last finished minute; a
// router whose IPS sensor inspects every packet is counted by the sensor every
// five seconds, and Live is its last thirty. Either way bytes × 8 / the span's
// seconds (`liveSeconds`) is the average rate over it, not a peak.

import { el, esc, pill, fmtBytes, fmtBps, protoPill, iso2Flag, renderSortHeader, sortRows, type SortState } from '../dom';
import { paletteColour, monoFont, TONE_TOKEN, type PillTone } from '../palette';
import type { Socket } from '../socket';
import { fmtTime } from '../timefmt';

const POLL_MS = 5000;

/** One group's totals, as every Top endpoint returns them. */
export interface Top { key: string; rx: number; tx: number; flows: number }
/** One group's bytes in one step of a series. */
export interface Point { ts: string; key: string; rx: number; tx: number }
interface Status {
  enabled: boolean; listening: boolean; port: number; listen: string; backend: string; storeError: string;
  records: number; lost: number; unknown: number; lastAt: number; coverage: number; conns: number;
  strays: number; addresses: number; source: string; ignored: number;
}
interface State {
  router: { enabled: boolean; interfaces: string; appliedAt: number; result: string };
  status: Status; live: Record<string, Top[]>; liveAt: number; liveSeconds: number; admin: boolean;
}
interface History { from: number; to: number; step: number; backend: string; top: Top[]; series: Point[] }
interface Flow {
  end: string; start: string; proto: number; host: string; hostPort: number; remote: string; remotePort: number;
  app: string; category: string; country: string; org: string; rx: number; tx: number; packets: number;
}
interface Settings {
  backend: string; chUrl: string; chUser: string; chDatabase: string; flowDays: number; port: number;
  collector: string; chPasswordSet: boolean;
}
interface Step { op: string; menu: string; what: string; error?: string }

declare const Chart: undefined | (new (canvas: HTMLElement, cfg: unknown) => { destroy(): void });

/** The average rate of a span's bytes, in bits per second. */
export function spanRate(bytes: number, seconds: number): number {
  return seconds > 0 ? (bytes * 8) / seconds : 0;
}

/** What Live covers, as its foot reads. */
export function spanLabel(seconds: number): string {
  return seconds >= 60 ? 'last minute' : 'last ' + seconds + ' s';
}

/** A group's label: a country carries its flag, the rest are themselves. */
export function keyLabel(dim: string, key: string): string {
  if (dim === 'country') return key ? (iso2Flag(key) + ' ' + key).trim() : 'Unknown';
  return key || '-';
}

/** An IP protocol number's name. */
export function protoName(p: number): string {
  return p === 6 ? 'tcp' : p === 17 ? 'udp' : p === 1 ? 'icmp' : String(p);
}

/** The colour each series is drawn in, in the order the keys come: the pill
 *  tones, then Other in the muted one. */
export const SERIES_TONES: PillTone[] = ['rx', 'tx', 'ok', 'warn', 'err', 'alt', 'pink'];

/**
 * A series as Chart.js stacks it: one dataset per key, in the order of `keys`
 * then Other, each with a value per step from `from` to `to` (a step with no
 * point is 0, so a stack never has a hole), in bits per second.
 */
export function seriesDatasets(points: Point[], keys: string[], from: number, to: number, step: number):
  { labels: number[]; sets: { key: string; data: number[] }[] } {
  const labels: number[] = [];
  const first = Math.floor(from / 1000 / step) * step;
  for (let t = first; t * 1000 < to; t += step) labels.push(t * 1000);
  const index = new Map(labels.map((t, i) => [t, i]));
  const order = [...keys];
  if (points.some((p) => p.key === 'Other')) order.push('Other');
  const sets = order.map((key) => ({ key, data: labels.map(() => 0) }));
  const byKey = new Map(sets.map((s) => [s.key, s]));
  for (const p of points) {
    const i = index.get(Date.parse(p.ts));
    const s = byKey.get(p.key);
    if (i === undefined || !s) continue;
    s.data[i] = ((p.rx + p.tx) * 8) / step;
  }
  return { labels, sets };
}

/** The collector's state as a pill. */
export function statePill(st: Status): string {
  if (!st.enabled) return pill('not set up', 'muted');
  if (st.source === 'sensor') {
    return !st.lastAt || Date.now() - st.lastAt > 30000 ? pill('no counts', 'warn') : pill('sensor live', 'ok');
  }
  if (!st.listening) return pill('not listening', 'err');
  if (!st.lastAt || Date.now() - st.lastAt > 3 * 60000) return pill('no IPFIX', 'warn');
  return pill('receiving', 'ok');
}

const DIM_LABEL: Record<string, string> = { app: 'Application', category: 'Category', host: 'Host', country: 'Country' };

function call<T>(url: string, init?: RequestInit): Promise<T> {
  return fetch(url, { credentials: 'same-origin', ...init }).then((r) =>
    r.json().then((d) => (r.ok ? d as T : Promise.reject(new Error((d && d.error) || r.statusText)))));
}

function post<T>(url: string, body?: unknown): Promise<T> {
  return call<T>(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
}

export function initTrafficAnalysisPage(socket: Socket, isVisible: (page: string) => boolean): void {
  let routerId = '';
  let state: State | null = null;
  let timer: ReturnType<typeof setInterval> | null = null;
  let tab = 'live';
  let liveDim = 'app';
  let hist: History | null = null;
  let flows: Flow[] = [];
  let chart: { destroy(): void } | null = null;
  // The History tab's filters, set by clicking a row: one host, app or country.
  const filters: Record<string, string> = {};
  let settingsFor = '';
  const liveSort: SortState = { col: 'total', dir: 'desc' };
  const histSort: SortState = { col: 'total', dir: 'desc' };
  const flowSort: SortState = { col: 'end', dir: 'desc' };

  const setText = (id: string, t: string): void => { const n = el(id); if (n) n.textContent = t; };
  const setHTML = (id: string, h: string): void => { const n = el(id); if (n) n.innerHTML = h; };
  const q = (id: string): string => (el<HTMLInputElement>(id)?.value || '').trim();
  const qs = (): string => '?router=' + encodeURIComponent(routerId);

  function load(): void {
    if (!routerId || !isVisible('traffic-analysis')) return;
    const asked = routerId;
    call<State>('/api/traffic/state' + qs())
      .then((s) => { if (asked === routerId) { state = s; draw(); } })
      .catch((e: Error) => setText('taStatus', e.message));
  }

  function drawCards(s: State): void {
    const st = s.status;
    const apps = s.live.app || [];
    let rx = 0;
    let tx = 0;
    for (const t of apps) { rx += t.rx; tx += t.tx; }
    setText('taRxVal', s.liveAt ? fmtBps(spanRate(rx, s.liveSeconds)) : '-');
    setText('taTxVal', s.liveAt ? fmtBps(spanRate(tx, s.liveSeconds)) : '-');
    setText('taRxFoot', spanLabel(s.liveSeconds));
    setText('taTxFoot', spanLabel(s.liveSeconds));
    setText('taRecordsLabel', st.source === 'sensor' ? 'Sensor counts' : 'IPFIX records');
    setText('taCoverageVal', st.records ? Math.round(st.coverage * 100) + ' %' : '-');
    setText('taCoverageFoot', st.conns + ' connections named by the sensor');
    setText('taRecordsVal', st.records ? st.records.toLocaleString() : '-');
    setText('taRecordsFoot', (st.lost ? st.lost.toLocaleString() + ' lost' : 'none lost') +
      (st.unknown ? ', ' + st.unknown + ' before their template' : ''));
    setHTML('taStatePill', statePill(st));
    setHTML('taBackendPill', pill(st.backend === 'clickhouse' ? 'ClickHouse' : 'SQLite', st.storeError ? 'err' : 'alt'));
    const notes: string[] = [];
    if (!st.enabled) notes.push('This router is not set up: open Setup, then Apply.');
    else if (st.source === 'sensor') {
      notes.push('Counted by the IPS sensor, which inspects every packet: Live is the last ' + (s.liveSeconds || 30) +
        ' seconds, refreshed every five.' + (st.ignored ? ' ' + st.ignored + ' IPFIX records were ignored: remove Traffic Flow in Setup.' : ''));
    } else if (!st.listening) notes.push('Not listening on udp/' + st.port + ': ' + st.listen);
    else if (!st.lastAt) notes.push('Listening on udp/' + st.port + '; no IPFIX from this router yet (' + st.addresses + ' of its addresses known).');
    if (st.storeError) notes.push('Storage: ' + st.storeError);
    if (st.strays) notes.push(st.strays + ' datagrams from no known router were dropped.');
    setText('taStatus', notes.join(' '));
    const badge = el('taBadge');
    if (badge) {
      badge.textContent = String(apps.length);
      badge.className = 'card-badge' + (apps.length ? ' active-blue' : '');
    }
  }

  function topRows(rows: Top[], dim: string, clickable: boolean): string {
    let max = 1;
    for (const t of rows) max = Math.max(max, t.rx + t.tx);
    return rows.map((t) => {
      const share = Math.round(((t.rx + t.tx) / max) * 100);
      const label = dim === 'app' || dim === 'category' ? pill(keyLabel(dim, t.key), 'alt') : esc(keyLabel(dim, t.key));
      return '<tr' + (clickable ? ' class="clickable" data-takey="' + esc(t.key) + '"' : '') + '>' +
        '<td>' + label + '</td>' +
        '<td style="color:var(--accent-rx)">' + esc(fmtBytes(t.rx)) + '</td>' +
        '<td style="color:var(--accent-tx)">' + esc(fmtBytes(t.tx)) + '</td>' +
        '<td><div class="ta-bar" style="width:' + share + '%;height:6px;border-radius:2px;background:var(--accent-rx)"></div></td>' +
        '<td>' + t.flows.toLocaleString() + '</td></tr>';
    }).join('');
  }

  function withTotal(rows: Top[]): (Top & { total: number })[] {
    return rows.map((t) => ({ ...t, total: t.rx + t.tx }));
  }

  function drawLive(s: State): void {
    renderSortHeader('taLiveHead', [
      { key: 'key', label: DIM_LABEL[liveDim] || '' }, { key: 'rx', label: 'Received' }, { key: 'tx', label: 'Sent' },
      { key: 'total', label: 'Share' }, { key: 'flows', label: 'Connections' },
    ], liveSort, () => drawLive(s));
    const rows = sortRows(withTotal(s.live[liveDim] || []), liveSort.col, liveSort.dir);
    setText('taLiveAt', s.liveAt ? (s.liveSeconds >= 60 ? 'Minute from ' + fmtTime(s.liveAt) + ', bytes over that minute'
      : 'The last ' + s.liveSeconds + ' seconds, bytes over them') : '');
    setHTML('taLiveRows', rows.length ? topRows(rows, liveDim, false)
      : '<tr><td colspan="5" class="empty-state">Nothing counted yet</td></tr>');
  }

  function draw(): void {
    if (!state) return;
    drawCards(state);
    if (tab === 'live') drawLive(state);
    if (tab === 'setup') drawSetup(state);
  }

  function clear(): void {
    state = null;
    hist = null;
    flows = [];
    settingsFor = '';
    for (const k of Object.keys(filters)) delete filters[k];
    if (chart) { chart.destroy(); chart = null; }
    setText('taStatus', '');
    setHTML('taLiveRows', '<tr><td colspan="5" class="empty-state">Nothing counted yet</td></tr>');
    setHTML('taHistRows', '<tr><td colspan="5" class="empty-state">Not read yet</td></tr>');
    setHTML('taFlowsRows', '<tr><td colspan="8" class="empty-state">Not searched yet</td></tr>');
    setHTML('taPlanRows', '<tr><td colspan="4" class="empty-state">Not previewed yet</td></tr>');
    setHTML('taPlanWarnings', '');
  }

  function start(): void {
    stop();
    load();
    timer = setInterval(load, POLL_MS);
    if (tab === 'history') loadHistory();
  }
  function stop(): void {
    if (timer) clearInterval(timer);
    timer = null;
  }

  document.addEventListener('mikrodash:pagechange', (e) => {
    if ((e as CustomEvent).detail === 'traffic-analysis') start();
    else stop();
  });
  socket.on('router:active', (d) => { if (d && d.activeId && d.activeId !== routerId) { routerId = d.activeId; clear(); load(); } });
  socket.on('router:switched', (d) => { routerId = (d && d.activeId) || ''; clear(); load(); });

  // ── tabs ─────────────────────────────────────────────────────────────────
  function showTab(key: string): void {
    tab = key;
    for (const k of ['live', 'history', 'flows', 'setup']) {
      const p = el('taPanel-' + k);
      if (p) p.style.display = k === key ? '' : 'none';
    }
    document.querySelectorAll('#taTabs [data-tatab]').forEach((b) => {
      const on = b.getAttribute('data-tatab') === key;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    if (key === 'history') loadHistory();
    if (key === 'flows' && !flows.length) searchFlows();
    draw();
  }
  el('taTabs')?.addEventListener('click', (e) => {
    const key = (e.target as HTMLElement | null)?.closest?.('[data-tatab]')?.getAttribute('data-tatab');
    if (key) showTab(key);
  });
  el('taLiveDims')?.addEventListener('click', (e) => {
    const d = (e.target as HTMLElement | null)?.closest?.('[data-tadim]')?.getAttribute('data-tadim');
    if (!d) return;
    liveDim = d;
    document.querySelectorAll('#taLiveDims [data-tadim]').forEach((b) =>
      b.classList.toggle('is-on', b.getAttribute('data-tadim') === d));
    if (state) drawLive(state);
  });

  // ── history ──────────────────────────────────────────────────────────────
  function histDim(): string { return el<HTMLSelectElement>('taHistDim')?.value || 'app'; }

  function drawFilters(): void {
    setHTML('taHistFilters', Object.keys(filters).map((k) => '<span class="chip is-on">' +
      esc(DIM_LABEL[k] + ': ' + keyLabel(k, filters[k] || '')) +
      '<button class="chip-x" type="button" title="Remove" data-taunfilter="' + esc(k) + '">×</button></span>').join(' '));
  }

  function loadHistory(): void {
    if (!routerId) return;
    const dim = histDim();
    let url = '/api/traffic/history' + qs() + '&dim=' + dim + '&range=' + (el<HTMLSelectElement>('taHistRange')?.value || '24h');
    for (const k of Object.keys(filters)) url += '&' + k + '=' + encodeURIComponent(filters[k] || '');
    setText('taHistMsg', 'Reading…');
    const asked = routerId;
    call<History>(url).then((h) => {
      if (asked !== routerId) return;
      hist = h;
      setText('taHistMsg', h.backend === 'clickhouse' ? 'From ClickHouse' : 'From SQLite');
      drawHistory();
    }).catch((e: Error) => setText('taHistMsg', e.message));
    drawFilters();
  }

  function drawHistory(): void {
    const h = hist;
    if (!h) return;
    const dim = histDim();
    renderSortHeader('taHistHead', [
      { key: 'key', label: DIM_LABEL[dim] || '' }, { key: 'rx', label: 'Received' }, { key: 'tx', label: 'Sent' },
      { key: 'total', label: 'Share' }, { key: 'flows', label: 'Connections' },
    ], histSort, drawHistory);
    const rows = sortRows(withTotal(h.top), histSort.col, histSort.dir);
    setHTML('taHistRows', rows.length ? topRows(rows, dim, true)
      : '<tr><td colspan="5" class="empty-state">Nothing in this range</td></tr>');
    drawChart(h, dim);
  }

  function drawChart(h: History, dim: string): void {
    const canvas = el('taHistChart');
    if (chart) { chart.destroy(); chart = null; }
    if (!canvas || typeof Chart === 'undefined') return;
    const keys = h.top.slice(0, SERIES_TONES.length).map((t) => t.key);
    const { labels, sets } = seriesDatasets(h.series, keys, h.from, h.to, h.step);
    const font = { family: monoFont(), size: 10 };
    chart = new Chart(canvas, {
      type: 'line',
      data: {
        labels,
        datasets: sets.map((s, i) => {
          const token = TONE_TOKEN[s.key === 'Other' ? 'muted' : (SERIES_TONES[i] || 'muted')];
          return { label: keyLabel(dim, s.key), data: s.data, fill: true, stack: 'bytes', pointRadius: 0, tension: 0.25,
            borderWidth: 1, borderColor: paletteColour(token), backgroundColor: paletteColour(token, 0.35) };
        }),
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: true, position: 'bottom', labels: { font, boxWidth: 10 } },
          tooltip: { titleFont: font, bodyFont: font, callbacks: {
            title: (items: Array<{ parsed: { x: number } }>): string => (items[0] ? fmtTime(labels[items[0].parsed.x] || 0) : ''),
            label: (i: { dataset: { label: string }; parsed: { y: number } }): string => ' ' + i.dataset.label + ': ' + fmtBps(i.parsed.y),
          } },
        },
        scales: {
          x: { ticks: { font, maxTicksLimit: 8, callback: (_v: number, i: number): string => fmtTime(labels[i] || 0) },
            grid: { display: false } },
          y: { stacked: true, beginAtZero: true, ticks: { font, callback: (v: number): string => fmtBps(v) } },
        },
      },
    });
  }

  el('taHistDim')?.addEventListener('change', loadHistory);
  el('taHistRange')?.addEventListener('change', loadHistory);
  el('taHistRows')?.addEventListener('click', (e) => {
    const k = (e.target as HTMLElement | null)?.closest?.('[data-takey]')?.getAttribute('data-takey');
    if (k === null || k === undefined) return;
    const dim = histDim();
    filters[dim] = k;
    // Drill down: a host's applications, an application's hosts, a country's hosts.
    const next = dim === 'host' ? 'app' : 'host';
    const sel = el<HTMLSelectElement>('taHistDim');
    if (sel && !filters[next]) sel.value = next;
    loadHistory();
  });
  el('taHistFilters')?.addEventListener('click', (e) => {
    const k = (e.target as HTMLElement | null)?.closest?.('[data-taunfilter]')?.getAttribute('data-taunfilter');
    if (!k) return;
    delete filters[k];
    loadHistory();
  });

  // ── flows ────────────────────────────────────────────────────────────────
  function drawFlows(source: string): void {
    renderSortHeader('taFlowsHead', [
      { key: 'end', label: 'Time' }, { key: 'host', label: 'Host' }, { key: 'remote', label: 'Remote' },
      { key: 'proto', label: 'Proto' }, { key: 'app', label: 'Application' }, { key: 'country', label: 'Country' },
      { key: 'rx', label: 'Received' }, { key: 'tx', label: 'Sent' },
    ], flowSort, () => drawFlows(source));
    const rows = sortRows(flows, flowSort.col, flowSort.dir);
    setHTML('taFlowsRows', rows.length ? rows.map((f) => '<tr>' +
      '<td>' + esc(fmtTime(Date.parse(f.end))) + '</td>' +
      '<td>' + esc(f.host) + ':' + f.hostPort + '</td>' +
      '<td>' + esc(f.remote) + ':' + f.remotePort + (f.org ? ' <span class="muted-note">' + esc(f.org) + '</span>' : '') + '</td>' +
      '<td>' + protoPill(protoName(f.proto)) + '</td>' +
      '<td>' + pill(f.app, f.app === 'Unknown' ? 'muted' : 'alt') + (f.category ? ' <span class="muted-note">' + esc(f.category) + '</span>' : '') + '</td>' +
      '<td>' + esc(keyLabel('country', f.country)) + '</td>' +
      '<td style="color:var(--accent-rx)">' + (f.rx ? esc(fmtBytes(f.rx)) : '') + '</td>' +
      '<td style="color:var(--accent-tx)">' + (f.tx ? esc(fmtBytes(f.tx)) : '') + '</td></tr>').join('')
      : '<tr><td colspan="8" class="empty-state">No flow matches</td></tr>');
  }

  function searchFlows(): void {
    if (!routerId) return;
    let url = '/api/traffic/flows' + qs() + '&range=' + (el<HTMLSelectElement>('taFlowRange')?.value || '1h');
    for (const [id, k] of [['taFlowHost', 'host'], ['taFlowRemote', 'remote'], ['taFlowApp', 'app'], ['taFlowCountry', 'country']] as const) {
      const v = k === 'country' ? q(id).toUpperCase() : q(id);
      if (v) url += '&' + k + '=' + encodeURIComponent(v);
    }
    setText('taFlowMsg', 'Searching…');
    call<{ source: string; flows: Flow[] }>(url).then((d) => {
      flows = d.flows;
      setText('taFlowMsg', d.source === 'memory'
        ? flows.length + ' flows from the last fifteen minutes in memory (SQLite keeps no flows; ClickHouse does)'
        : flows.length + ' flows from ClickHouse');
      drawFlows(d.source);
    }).catch((e: Error) => setText('taFlowMsg', e.message));
  }
  el('taFlowSearch')?.addEventListener('click', searchFlows);

  // ── setup ────────────────────────────────────────────────────────────────
  function syncBackend(): void {
    const ch = el<HTMLSelectElement>('taBackend')?.value === 'clickhouse';
    document.querySelectorAll('.ta-ch').forEach((n) => { (n as HTMLElement).style.display = ch ? '' : 'none'; });
  }

  function drawSetup(s: State): void {
    setText('taSetupNote', !s.admin ? 'Traffic Analysis is configured by administrators.'
      : s.status.source === 'sensor'
        ? 'This router\'s IPS sensor inspects every packet and counts the volumes itself: Traffic Flow is not needed. Preview shows its removal.'
        : 'Choose where the totals are kept, then apply Traffic Flow to this router. The IPS sensor names the applications; without it, traffic is counted under the remote organisation and port.');
    for (const id of ['taSettingsForm', 'taRouterForm', 'taPlanShow', 'taApply', 'taRemove']) {
      const n = el(id);
      if (n) n.style.display = s.admin ? '' : 'none';
    }
    if (!s.admin || settingsFor === routerId) return;
    settingsFor = routerId;
    const iface = el<HTMLInputElement>('taInterfaces');
    if (iface) iface.value = s.router.interfaces;
    call<Settings>('/api/traffic/settings').then((st) => {
      const set = (id: string, v: string): void => { const n = el<HTMLInputElement>(id); if (n) n.value = v; };
      set('taBackend', st.backend);
      set('taPort', String(st.port));
      set('taCollector', st.collector);
      set('taChUrl', st.chUrl);
      set('taChUser', st.chUser);
      set('taChDatabase', st.chDatabase);
      set('taFlowDays', String(st.flowDays));
      set('taChPassword', '');
      setText('taChPasswordHelp', st.chPasswordSet ? 'Set, stored encrypted. Empty keeps it.' : 'Stored encrypted.');
      syncBackend();
    }).catch((e: Error) => setText('taSettingsMsg', e.message));
  }
  el('taBackend')?.addEventListener('change', syncBackend);
  el('taSettingsForm')?.addEventListener('submit', (ev) => {
    ev.preventDefault();
    setText('taSettingsMsg', 'Saving…');
    post('/api/traffic/settings', {
      backend: el<HTMLSelectElement>('taBackend')?.value || 'sqlite', port: Number(q('taPort')) || 2055,
      collector: q('taCollector'), chUrl: q('taChUrl'), chUser: q('taChUser'), chPassword: q('taChPassword'),
      chDatabase: q('taChDatabase'), flowDays: Number(q('taFlowDays')) || 0,
    }).then(() => { setText('taSettingsMsg', 'Saved.'); settingsFor = ''; load(); })
      .catch((e: Error) => setText('taSettingsMsg', e.message));
  });
  el('taRouterForm')?.addEventListener('submit', (ev) => {
    ev.preventDefault();
    post('/api/traffic/router' + qs(), { interfaces: q('taInterfaces') })
      .then(() => setText('taRouterMsg', 'Saved: Preview shows what Apply changes.'))
      .catch((e: Error) => setText('taRouterMsg', e.message));
  });

  function drawPlan(steps: Step[], warnings: string[], done: boolean): void {
    setHTML('taPlanWarnings', warnings.map((w) => '<div class="muted-note mb-2">' + pill('note', 'warn') + ' ' + esc(w) + '</div>').join(''));
    setHTML('taPlanRows', steps.length ? steps.map((s) => '<tr><td>' + pill(s.op, s.op === 'remove' ? 'err' : s.op === 'add' ? 'ok' : 'rx') +
      '</td><td>' + esc(s.menu) + '</td><td>' + esc(s.what) + '</td><td>' +
      (!done ? '-' : s.error ? pill('failed', 'err') + ' ' + esc(s.error) : pill('done', 'ok')) + '</td></tr>').join('')
      : '<tr><td colspan="4" class="empty-state">The router already holds what it needs</td></tr>');
  }
  el('taPlanShow')?.addEventListener('click', () => {
    setText('taPlanMsg', 'Reading Traffic Flow…');
    call<{ steps: Step[]; warnings: string[] }>('/api/traffic/plan' + qs())
      .then((p) => { setText('taPlanMsg', ''); drawPlan(p.steps, p.warnings, false); })
      .catch((e: Error) => setText('taPlanMsg', e.message));
  });
  function apply(remove: boolean): void {
    const ask = remove
      ? 'Remove MikroDash\'s Traffic Flow target from the router? Traffic Flow is turned off only if no other target is left.'
      : 'Write Traffic Flow to the router? It exports every connection once a minute to MikroDash.';
    if (!window.confirm(ask)) return;
    setText('taPlanMsg', 'Writing…');
    post<{ ok: boolean; steps: Step[]; warnings: string[] }>('/api/traffic/apply' + qs() + (remove ? '&remove=1' : ''))
      .then((r) => {
        setText('taPlanMsg', r.ok ? (remove ? 'Removed.' : 'Applied: the first minute arrives within two minutes.')
          : 'Stopped at a failed step: preview again to see what is left.');
        drawPlan(r.steps, r.warnings, true);
        load();
      })
      .catch((e: Error) => setText('taPlanMsg', e.message));
  }
  el('taApply')?.addEventListener('click', () => apply(false));
  el('taRemove')?.addEventListener('click', () => apply(true));
}
