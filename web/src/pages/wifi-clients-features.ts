// The Wifi Clients page's two optional features (Settings -> Features):
//
//   watch list      a star on a client's row, and a card of watched devices
//                   with whether each is here; an alert fires when one is gone
//                   longer than its grace (internal/server/features_loop.go)
//   client history  a client's name opens its signal and access point over
//                   the last hours, from the samples the server writes a minute
//                   for the routers it is switched on for
//
// Both are about the router being viewed, so both follow the router switch.

import type { Socket } from '../socket';
import type { WirelessClient } from '../gen/payloads';
import { esc, el, pill, renderSortHeader, sortRows, type SortCol, type SortState } from '../dom';
import { paletteCss, type PaletteToken } from '../palette';
import { featureOn, onFeatures } from '../caps';
import { fmtTime } from '../timefmt';

interface Watched {
  id: number; routerId: string; mac: string; label: string; graceMinutes: number;
  present: boolean; known: boolean; fixed: boolean; lastSeen: number;
}

interface Sample { ts: number; mac: string; iface: string; ap: string; ssid: string; signal: number | null; txRate: string }

/** One colour per access point in a client's history, from the palette. */
const AP_COLOURS: PaletteToken[] = ['--accent-rx', '--accent-tx', '--accent-alt', '--accent-pink', '--accent-warn',
  '--accent-ok'];

/** A gap longer than this between two samples is the client being away. */
const AWAY_MS = 3 * 60_000;

const FIXED_NOTE = 'Seen only through a static or DHCP-made ARP entry, which the router never probes, ' +
  'so whether it is here cannot be told and no alert is raised.';

const COLS_W: SortCol[] = [
  { key: 'label', label: 'Label' },
  { key: 'mac', label: 'MAC' },
  { key: 'state', label: 'Now' },
  { key: 'graceMinutes', label: 'Grace' },
  { label: '' },
];

function call<T>(url: string, init?: RequestInit): Promise<T> {
  return fetch(url, { credentials: 'same-origin', ...init }).then((r) =>
    r.json().then((d) => (r.ok ? d as T : Promise.reject(new Error((d && d.error) || r.statusText)))));
}

/**
 * The history as the chart and the list read it: the line broken where the
 * client was away, and each change of access point and each absence as an
 * event. Pure, so the reading is tested without a DOM.
 */
export function historyEvents(samples: Sample[]): Array<{ ts: number; text: string }> {
  const out: Array<{ ts: number; text: string }> = [];
  let prev: Sample | null = null;
  for (const s of samples) {
    const where = s.ap || s.iface;
    if (!prev) {
      out.push({ ts: s.ts, text: 'on ' + where });
    } else if (s.ts - prev.ts > AWAY_MS) {
      out.push({ ts: prev.ts, text: 'gone for ' + Math.round((s.ts - prev.ts) / 60_000) + ' min' });
      out.push({ ts: s.ts, text: 'back on ' + where });
    } else if (where !== (prev.ap || prev.iface)) {
      out.push({ ts: s.ts, text: 'moved to ' + where });
    }
    prev = s;
  }
  return out;
}

function chart(samples: Sample[], from: number, to: number): string {
  const W = 640, H = 160, top = -30, bottom = -95;
  const x = (ts: number): number => ((ts - from) / Math.max(1, to - from)) * W;
  const y = (sig: number): number => ((top - Math.max(bottom, Math.min(top, sig))) / (top - bottom)) * H;
  const aps = [...new Set(samples.map((s) => s.ap || s.iface))];
  const colour = (ap: string): string => paletteCss(AP_COLOURS[aps.indexOf(ap) % AP_COLOURS.length]!);
  let path = '';
  let prev: Sample | null = null;
  for (const s of samples) {
    if (s.signal === null) continue;
    path += (prev && s.ts - prev.ts <= AWAY_MS ? 'L' : 'M') + x(s.ts).toFixed(1) + ',' + y(s.signal).toFixed(1);
    prev = s;
  }
  const dots = samples.filter((s) => s.signal !== null).map((s) =>
    '<circle cx="' + x(s.ts).toFixed(1) + '" cy="' + y(s.signal!).toFixed(1) + '" r="1.8" style="fill:' +
    colour(s.ap || s.iface) + '"><title>' + esc(fmtTime(s.ts) + ' · ' + s.signal + ' dBm · ' + (s.ap || s.iface)) +
    '</title></circle>').join('');
  const grid = [-40, -60, -75, -90].map((v) =>
    '<line x1="0" x2="' + W + '" y1="' + y(v) + '" y2="' + y(v) + '" class="wl-hist-grid"/>' +
    '<text x="2" y="' + (y(v) - 2) + '" class="wl-hist-axis">' + v + '</text>').join('');
  const legend = aps.map((ap) => '<span class="wl-hist-key"><i style="background:' + colour(ap) + '"></i>' +
    esc(ap) + '</span>').join('');
  return '<svg viewBox="0 0 ' + W + ' ' + H + '" class="wl-hist-chart" preserveAspectRatio="none">' + grid +
    '<path d="' + path + '" class="wl-hist-line"/>' + dots + '</svg><div class="wl-hist-legend">' + legend + '</div>';
}

export interface ClientFeatures {
  /** The star at the end of a client's name cell, or ''. */
  watchCell(c: WirelessClient): string;
  /** Attributes that make a client's name open its history, or ''. */
  nameAttrs(c: WirelessClient): string;
}

export function initClientFeatures(socket: Socket, rerender: () => void): ClientFeatures {
  let routerId = '';
  let watched: Watched[] = [];
  let recording = false;
  let histMac = '';
  let histLabel = '';
  let histHours = 24;
  let tick: ReturnType<typeof setInterval> | null = null;
  const sortW: SortState = { col: 'label', dir: 'asc' };

  const watchedMacs = (): Set<string> => new Set(watched.map((w) => w.mac.toUpperCase()));

  function syncCards(): void {
    const wc = el('wlWatchCard');
    if (wc) wc.style.display = featureOn('watchListEnabled') ? '' : 'none';
    const rc = el('wlRecCard');
    if (rc) rc.style.display = featureOn('wifiHistoryEnabled') && routerId ? '' : 'none';
    const tg = el('wlRecToggle');
    if (tg) tg.textContent = recording ? 'Stop recording' : 'Record this router';
    const hc = el('wlHistCard');
    if (hc && (!featureOn('wifiHistoryEnabled') || !histMac)) hc.style.display = 'none';
  }

  function loadRecording(): void {
    if (!featureOn('wifiHistoryEnabled') || !routerId) { recording = false; syncCards(); return; }
    call<{ recording: boolean }>('/api/wifi/history/status?routerId=' + encodeURIComponent(routerId))
      .then((d) => { recording = d.recording; })
      .catch(() => { recording = false; })
      .then(syncCards);
  }

  function setRecording(on: boolean): void {
    call<{ recording: boolean }>('/api/wifi/history/record', { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ routerId, on }) })
      .then((d) => { recording = d.recording; const n = el('wlRecNote'); if (n) n.textContent = ''; syncCards(); })
      .catch((e: Error) => { const n = el('wlRecNote'); if (n) n.textContent = 'not saved: ' + e.message; });
  }

  function renderWatch(): void {
    renderSortHeader('wlWatchThead', COLS_W, sortW, renderWatch);
    const body = el('wlWatchTable');
    const badge = el('wlWatchBadge');
    if (badge) badge.textContent = String(watched.length);
    if (!body) return;
    const rows = watched.map((w) => ({ ...w, state: !w.known ? 'unknown' : w.present ? 'here' : 'gone' }));
    const hint = el('wlWatchHint');
    if (hint) {
      hint.textContent = watched.some((w) => w.fixed) ? FIXED_NOTE : '';
      hint.style.display = hint.textContent ? '' : 'none';
    }
    body.innerHTML = rows.length ? sortRows(rows, sortW.col, sortW.dir).map((w) =>
      '<tr><td>' + esc(w.label || '-') + '</td><td class="mono">' + esc(w.mac) + '</td>' +
      '<td>' + (w.fixed ? '<span title="' + esc(FIXED_NOTE) + '">' : '<span>') +
        pill(w.state, w.state === 'here' ? 'ok' : w.state === 'gone' ? 'err' : 'muted') + '</span>' +
        (w.state === 'gone' && w.lastSeen ? ' last seen ' + esc(fmtTime(w.lastSeen)) : '') + '</td>' +
      '<td>' + w.graceMinutes + ' min</td>' +
      '<td class="text-end"><button class="sbtn sbtn-danger is-sm" type="button" data-unwatch="' + esc(w.mac) +
        '">Remove</button></td></tr>').join('')
      : '<tr><td colspan="5" class="empty-state">Nothing watched. Star a client, or add a MAC above.</td></tr>';
  }

  function loadWatch(): void {
    if (!featureOn('watchListEnabled') || !routerId) { watched = []; syncCards(); return; }
    call<{ devices: Watched[] }>('/api/watch?routerId=' + encodeURIComponent(routerId))
      .then((d) => { watched = d.devices; })
      .catch(() => { watched = []; })
      .then(() => { syncCards(); renderWatch(); rerender(); });
  }

  function saveWatch(mac: string, label: string, grace: number): void {
    call('/api/watch', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ routerId, mac, label, graceMinutes: grace }) })
      .then(loadWatch)
      .catch((e: Error) => { const n = el('wlWatchNote'); if (n) n.textContent = 'not saved: ' + e.message; });
  }

  function unwatch(mac: string): void {
    call('/api/watch?routerId=' + encodeURIComponent(routerId) + '&mac=' + encodeURIComponent(mac), { method: 'DELETE' })
      .then(loadWatch).catch(() => { /* the list re-reads on the next visit */ });
  }

  function loadHistory(): void {
    const card = el('wlHistCard');
    const body = el('wlHistBody');
    if (!card || !body || !histMac || !routerId) return;
    card.style.display = '';
    const title = el('wlHistTitle');
    if (title) title.textContent = 'History: ' + histLabel;
    body.innerHTML = '<span class="empty-state">reading…</span>';
    call<{ samples: Sample[]; from: number; to: number }>('/api/wifi/history?routerId=' + encodeURIComponent(routerId) +
      '&mac=' + encodeURIComponent(histMac) + '&hours=' + histHours)
      .then((d) => {
        if (!d.samples.length) {
          body.innerHTML = '<span class="empty-state">No samples yet: the history is written once a minute ' +
            'from when this router was set to be recorded.</span>';
          return;
        }
        const events = historyEvents(d.samples).slice(-30).reverse();
        body.innerHTML = chart(d.samples, d.from, d.to) +
          '<div class="wl-hist-events">' + events.map((e) =>
            '<div><span class="mono">' + esc(fmtTime(e.ts)) + '</span> ' + esc(e.text) + '</div>').join('') + '</div>';
      })
      .catch((e: Error) => { body.innerHTML = '<span class="empty-state">Not read: ' + esc(e.message) + '</span>'; });
  }

  // ── wiring ───────────────────────────────────────────────────────────────

  el('wirelessTable')?.addEventListener('click', (ev) => {
    const t = ev.target as HTMLElement;
    const star = t.closest?.('[data-watch]') as HTMLElement | null;
    if (star) {
      const mac = star.getAttribute('data-watch') || '';
      if (watchedMacs().has(mac.toUpperCase())) unwatch(mac);
      else saveWatch(mac, star.getAttribute('data-label') || '', 10);
      return;
    }
    const name = t.closest?.('[data-wlhist]') as HTMLElement | null;
    if (name) {
      histMac = name.getAttribute('data-wlhist') || '';
      histLabel = name.textContent || histMac;
      loadHistory();
    }
  });
  el('wlWatchTable')?.addEventListener('click', (ev) => {
    const b = (ev.target as HTMLElement).closest?.('[data-unwatch]') as HTMLElement | null;
    if (b) unwatch(b.getAttribute('data-unwatch') || '');
  });
  el('wlWatchAdd')?.addEventListener('click', () => {
    const mac = (el<HTMLInputElement>('wlWatchMac')?.value || '').trim();
    const label = (el<HTMLInputElement>('wlWatchLabel')?.value || '').trim();
    const grace = Number(el<HTMLInputElement>('wlWatchGrace')?.value) || 10;
    if (mac) saveWatch(mac, label, grace);
  });
  el('wlRecToggle')?.addEventListener('click', () => setRecording(!recording));
  el('wlHistClose')?.addEventListener('click', () => {
    histMac = '';
    const card = el('wlHistCard');
    if (card) card.style.display = 'none';
  });
  el('wlHistRange')?.addEventListener('change', () => {
    histHours = Number(el<HTMLSelectElement>('wlHistRange')?.value) || 24;
    loadHistory();
  });

  socket.on('router:active', (d) => { routerId = (d && d.activeId) || routerId; loadWatch(); loadRecording(); });
  socket.on('router:switched', (d) => {
    routerId = (d && d.activeId) || '';
    histMac = '';
    recording = false;
    syncCards();
    loadWatch();
    loadRecording();
  });
  document.addEventListener('mikrodash:pagechange', (e) => {
    if (tick) { clearInterval(tick); tick = null; }
    if ((e as CustomEvent).detail !== 'wifi-clients') return;
    loadWatch();
    loadRecording();
    // Presence moves on the server's minute; the card follows while it is shown.
    tick = setInterval(loadWatch, 60_000);
  });
  onFeatures(() => { syncCards(); loadWatch(); loadRecording(); rerender(); });
  syncCards();

  return {
    watchCell(c) {
      if (!featureOn('watchListEnabled')) return '';
      const on = watchedMacs().has((c.mac || '').toUpperCase());
      return ' <button class="icon-btn" type="button" data-watch="' + esc(c.mac) +
        '" data-label="' + esc(c.comment || c.name || '') + '" aria-pressed="' + on + '" title="' +
        (on ? 'Stop watching' : 'Watch: alert when it is gone') + '">' + (on ? '★' : '☆') + '</button>';
    },
    nameAttrs(c) {
      if (!featureOn('wifiHistoryEnabled')) return '';
      return ' data-wlhist="' + esc(c.mac) + '" class="wl-hist-link" title="Open its history"';
    },
  };
}
