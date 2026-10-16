// The DNS page's two on-demand tools (Settings -> Features): the cache
// browser and the domain route trace. Both read the router only when asked,
// see internal/server/dnstools_api.go.

import { esc, el, kv, pill, renderSortHeader, sortRows, type SortCol, type SortState } from '../dom';
import type { PillTone } from '../palette';
import { featureOn, onFeatures, settingsAllowed } from '../caps';
import type { Socket } from '../socket';

interface CacheRow { name: string; type: string; data: string; ttl: string }

interface TraceStep { step: string; state: string; text: string }

interface TraceMatch {
  id: string; name: string; regexp: string; type: string; value: string;
  addressList: string; disabled: boolean; how: string;
}

interface Trace {
  name: string;
  matches: TraceMatch[];
  /** Indexes into `matches`: the entries that decide the answer. */
  answering: number[];
  steps: TraceStep[];
}

const COLS_C: SortCol[] = [
  { key: 'name', label: 'Name' },
  { key: 'type', label: 'Type' },
  { key: 'data', label: 'Answer' },
  { key: 'ttl', label: 'TTL' },
];

/** A trace step's state as its pill says it. */
const STATE: Record<string, [string, PillTone]> = {
  ok: ['ok', 'ok'], warn: ['partly', 'warn'], fail: ['fails', 'err'], skip: ['not checked', 'muted'],
};

function getJSON<T>(url: string): Promise<T> {
  return fetch(url, { credentials: 'same-origin' }).then((r) =>
    r.json().then((d) => (r.ok ? d as T : Promise.reject(new Error((d && d.error) || r.statusText)))));
}

export function initDnsTools(socket: Socket): void {
  const sortC: SortState = { col: 'name', dir: 'asc' };
  let routerId = '';
  let cached: CacheRow[] = [];
  let cacheQuery = '';

  function syncCards(): void {
    // The server answers an administrator only; the card is not drawn for anyone
    // who could only be told so.
    const cache = el('dnsCacheCard');
    if (cache) cache.style.display = featureOn('dnsCacheEnabled') && settingsAllowed() ? '' : 'none';
    const trace = el('dnsTraceCard');
    if (trace) trace.style.display = featureOn('dnsTraceEnabled') ? '' : 'none';
  }

  // ── the cache ─────────────────────────────────────────────────────────────

  function renderCache(): void {
    renderSortHeader('dnsCacheThead', COLS_C, sortC, renderCache);
    const body = el('dnsCacheTable');
    if (!body) return;
    body.innerHTML = cached.length ? sortRows(cached, sortC.col, sortC.dir).map((c) =>
      '<tr><td class="mono">' + esc(c.name) + '</td><td>' + esc(c.type) + '</td>' +
      '<td class="mono" style="word-break:break-all">' + esc(c.data) + '</td><td>' + esc(c.ttl) + '</td></tr>').join('')
      : '<tr><td colspan="4" class="empty-state">' +
        (cacheQuery ? 'Nothing cached matches.' : 'The cache is empty.') + '</td></tr>';
  }

  function readCache(): void {
    const rid = routerId;
    const note = el('dnsCacheNote');
    if (!rid) return;
    const q = (el<HTMLInputElement>('dnsCacheSearch')?.value || '').trim();
    if (note) note.textContent = 'reading…';
    getJSON<{ total: number; cached: number; rows: CacheRow[] }>('/api/dns/cache?routerId=' +
      encodeURIComponent(rid) + '&q=' + encodeURIComponent(q))
      .then((d) => {
        // A slow read of the router that was selected is not this router's cache.
        if (rid !== routerId) return;
        cached = d.rows;
        cacheQuery = q;
        const badge = el('dnsCacheBadge');
        if (badge) badge.textContent = String(d.cached);
        if (note) {
          note.textContent = d.total + (q ? ' match' : ' cached') +
            (d.rows.length < d.total ? ', the first ' + d.rows.length + ' shown' : '');
        }
        renderCache();
      })
      .catch((e: Error) => { if (note && rid === routerId) note.textContent = 'not read: ' + e.message; });
  }
  el('dnsCacheRead')?.addEventListener('click', readCache);
  el('dnsCacheSearch')?.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Enter') readCache(); });

  // ── the trace ─────────────────────────────────────────────────────────────

  function renderTrace(t: Trace): string {
    const steps = t.steps.map((s) => {
      const [word, tone] = STATE[s.state] || ['', 'muted'];
      return kv(s.step, pill(word, tone) + ' ' + esc(s.text));
    }).join('');
    const others = t.matches.filter((_, i) => !t.answering.includes(i));
    return steps + (others.length
      ? kv('Also matching, not answering', esc(others.map((m) => (m.disabled ? 'disabled ' : '') + m.type + ' ' +
        (m.name || m.regexp)).join(', ')))
      : '');
  }

  function trace(): void {
    const rid = routerId;
    const out = el('dnsTraceOut');
    const name = (el<HTMLInputElement>('dnsTraceName')?.value || '').trim();
    if (!rid || !out || !name) return;
    out.innerHTML = '<span class="empty-state">reading…</span>';
    getJSON<Trace>('/api/dns/trace?routerId=' + encodeURIComponent(rid) + '&name=' + encodeURIComponent(name))
      .then((t) => { if (rid === routerId) out.innerHTML = renderTrace(t); })
      .catch((e: Error) => {
        if (rid === routerId) out.innerHTML = '<span class="empty-state">Not traced: ' + esc(e.message) + '</span>';
      });
  }
  el('dnsTraceGo')?.addEventListener('click', trace);
  el('dnsTraceName')?.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Enter') trace(); });

  // What was read belongs to the router it was read from.
  socket.on('router:active', (d) => { routerId = (d && d.activeId) || routerId; });
  socket.on('router:switched', (d) => {
    routerId = (d && d.activeId) || '';
    cached = [];
    cacheQuery = '';
    renderCache();
    const note = el('dnsCacheNote');
    if (note) note.textContent = '';
    const out = el('dnsTraceOut');
    if (out) out.innerHTML = '';
  });

  onFeatures(syncCards);
  syncCards();
}
