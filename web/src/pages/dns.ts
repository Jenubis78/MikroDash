// The DNS page - a port of the DNS IIFE in public/app.js.
//
// Line for line where it matters. The markup strings, the class names, the em
// dashes and the order of the key/value rows are the live app's, because the
// acceptance criterion for this page is that it renders identically, not that
// it renders correctly.

import { esc, el, resRow, debounce, renderSortHeader, sortMul, sortRows, pill, type SortCol, type SortState, kv } from '../dom';
import type { Socket } from '../socket';
import { mountAdds, mountRows, openResource } from '../resource';
import { initDnsFleet } from './dns-fleet';
import { initDnsTools } from './dns-tools';
import { initDnsBulk } from './dns-bulk';
import { initDnsLists } from './dns-lists';
import { onFeatures } from '../caps';
import type { DNSStaticEntry, DNSPayload } from '../gen/payloads';

const COLS_S: SortCol[] = [
  { key: 'name', label: 'Name' },
  { key: 'address', label: 'Value' },
  { key: 'type', label: 'Type' },
  { key: 'addressList', label: 'Address List' },
  { key: 'ttl', label: 'TTL' },
  { key: 'comment', label: 'Comment' },
];

const COLS_F: SortCol[] = [
  { key: 'name', label: 'Name' },
  { key: 'dnsServers', label: 'DNS Servers' },
  { key: 'dohServers', label: 'DoH Servers' },
  { key: 'usedBy', label: 'Used By' },
  { key: 'comment', label: 'Comment' },
];

const COLS_A: SortCol[] = [
  { key: 'source', label: 'Source' },
  { key: 'nameCount', label: 'Names', cls: 'text-end' },
  { key: 'matchCount', label: 'Matches', cls: 'text-end' },
  { key: 'certificate', label: 'Certificate' },
  { key: 'comment', label: 'Comment' },
];

export function initDnsPage(socket: Socket, isVisible: (page: string) => boolean): void {
  const settingsBody = el('dnsSettingsBody');
  if (!settingsBody) return;

  let data: DNSPayload | null = null;
  const sortS: SortState = { col: 'name', dir: 'asc' };
  let activeRouter = '';
  socket.on('router:active', (d) => { activeRouter = (d && d.activeId) || activeRouter; });
  socket.on('router:switched', (d) => { activeRouter = (d && d.activeId) || ''; });
  const bulk = initDnsBulk(() => activeRouter, () => renderStatic());
  initDnsLists();
  const sortF: SortState = { col: 'name', dir: 'asc' };
  const sortA: SortState = { col: 'source', dir: 'asc' };

  // The resolver's settings are the `dnsSettings` resource: one row with no
  // id of its own, which the engine calls "singleton". The shared form edits
  // it, with the same permission, audit and undo as any other row; a viewer
  // who may not write the page gets no form (openResource checks).
  el('dnsSettingsEdit')?.addEventListener('click', () => {
    openResource(socket, 'dnsSettings', { id: 'singleton' });
  });

  function renderSettings(): void {
    const s = data?.settings;
    if (!s) return;
    const servers = s.servers.length ? s.servers.join(', ')
      : s.dynamicServers.length ? s.dynamicServers.join(', ') + ' (dynamic)'
      : '-';
    let html = '';
    html += s.dohEnabled
      ? kv('DNS over HTTPS', esc(s.dohUrl), 'on') +
        kv('Certificate check', s.dohVerifyCert ? 'verified' : 'NOT verified',
          s.dohVerifyCert ? 'on' : 'warn')
      : kv('DNS over HTTPS', 'off', 'off');
    html += kv('Servers', esc(servers));
    html += kv('Allow remote requests', s.allowRemoteRequests ? 'yes' : 'no',
      s.allowRemoteRequests ? 'warn' : 'off');
    html += kv('Cache', (s.cacheUsed === null ? '-' : String(s.cacheUsed)) + ' / ' +
      (s.cacheSize === null ? '-' : String(s.cacheSize)) + ' KiB');
    html += kv('Cache max TTL', esc(s.cacheMaxTtl || '-'));
    html += kv('mDNS repeat', esc(s.mdnsRepeatIfaces.join(', ') || '-'));
    html += kv('Max UDP packet', s.maxUdpPacketSize === null ? '-' : String(s.maxUdpPacketSize));
    html += kv('Query timeout', esc(s.queryServerTimeout || '-') + ' / ' + esc(s.queryTotalTimeout || '-'));
    html += kv('Address list extra time', esc(s.addressListExtraTime || '-'));
    settingsBody!.innerHTML = html;
  }

  function sorted(rows: DNSStaticEntry[], sort: SortState): DNSStaticEntry[] {
    return rows.slice().sort((a, b) => {
      const av = ((a as unknown as Record<string, unknown>)[sort.col] ?? '').toString().toLowerCase();
      const bv = ((b as unknown as Record<string, unknown>)[sort.col] ?? '').toString().toLowerCase();
      return sortMul(sort) * av.localeCompare(bv);
    });
  }

  function renderStatic(): void {
    const rows = data?.staticEntries || [];
    const search = el<HTMLInputElement>('dnsStaticSearch');
    const q = (search?.value || '').toLowerCase().trim();
    const list = rows.filter((e) => {
      if (!q) return true;
      return [e.name || e.regexp, e.address, e.addressList, e.comment].join(' ')
        .toLowerCase().indexOf(q) !== -1;
    });
    const picking = bulk.on();
    const order = sorted(list, sortS);
    bulk.setRows(order);
    renderSortHeader('dnsStaticThead', picking ? [{ label: bulk.headCell() }, ...COLS_S] : COLS_S,
      sortS, () => render());
    const cols = el('dnsStaticCols');
    if (cols) {
      cols.innerHTML = (picking ? '<col style="width:34px">' : '') +
        '<col style="width:28%"><col style="width:20%"><col style="width:8%"><col style="width:14%">' +
        '<col style="width:8%"><col style="width:22%">';
    }
    const badge = el('dnsStaticBadge');
    if (badge) badge.textContent = String(rows.length);
    const table = el('dnsStaticTable');
    if (!table) return;
    // A regexp entry has no name, and its regexp is what identifies it: the
    // server finds the row by it and audits the write under it.
    table.innerHTML = list.length ? order.map((e) =>
      '<tr' + (e.disabled ? ' style="opacity:.55"' : '') + resRow(e.id, e.name || e.regexp) + '>' +
      (picking ? bulk.cell(e) : '') +
      '<td>' + esc(e.name || e.regexp) +
        (e.regexp ? ' ' + pill('regexp', 'alt') : '') +
        (e.matchSubdomain ? ' ' + pill('+sub', 'rx') : '') +
        (e.dynamic ? ' ' + pill('dynamic', 'muted') : '') + '</td>' +
      // A FWD entry with no forward-to goes to the resolver's own servers.
      '<td class="mono">' + esc(e.address || (e.type === 'FWD' ? 'default servers' : '')) + '</td>' +
      '<td>' + esc(e.type) + '</td>' +
      '<td class="mono">' + esc(e.addressList || '') + '</td>' +
      '<td>' + esc(e.ttl || '-') + '</td>' +
      '<td style="color:var(--text-muted)">' + esc(e.comment || '') + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="' + (picking ? 7 : 6) + '" class="empty-state">' +
        (q ? 'No entries match that search.' : 'No static DNS entries.') + '</td></tr>';
  }

  /** Forwarders and adlists: a card each, shown only where the router has the menu. */
  function renderForwarders(): void {
    const card = el('dnsFwdCard');
    if (card) card.style.display = data?.forwardersAvailable ? '' : 'none';
    const rows = data?.forwarders || [];
    renderSortHeader('dnsFwdThead', COLS_F, sortF, () => renderForwarders());
    const count = el('dnsFwdBadge');
    if (count) count.textContent = String(rows.length);
    const table = el('dnsFwdTable');
    if (!table) return;
    table.innerHTML = rows.length ? sortRows(rows, sortF.col, sortF.dir).map((f) =>
      '<tr' + (f.disabled ? ' style="opacity:.55"' : '') + resRow(f.id, f.name) + '>' +
      '<td>' + esc(f.name) + (f.disabled ? ' ' + pill('disabled', 'muted') : '') + '</td>' +
      '<td class="mono">' + esc(f.dnsServers.join(', ') || '-') + '</td>' +
      '<td class="mono">' + esc(f.dohServers.join(', ') || '-') +
        (f.dohServers.length && !f.verifyDohCert ? ' ' + pill('no cert check', 'warn') : '') + '</td>' +
      '<td>' + (f.usedBy ? f.usedBy + (f.usedBy === 1 ? ' entry' : ' entries') : '-') + '</td>' +
      '<td style="color:var(--text-muted)">' + esc(f.comment) + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="5" class="empty-state">No forwarders.</td></tr>';
  }

  function renderAdlists(): void {
    const card = el('dnsAdlistCard');
    if (card) card.style.display = data?.adlistsAvailable ? '' : 'none';
    const rows = (data?.adlists || []).map((a) => ({ ...a, source: a.url || a.file,
      certificate: a.url ? (a.sslVerify ? 'verified' : 'not verified') : '' }));
    renderSortHeader('dnsAdlistThead', COLS_A, sortA, () => renderAdlists());
    const count = el('dnsAdlistBadge');
    if (count) count.textContent = String(rows.length);
    const table = el('dnsAdlistTable');
    if (!table) return;
    const num = (n: number | null): string => (n === null ? '-' : n.toLocaleString());
    table.innerHTML = rows.length ? sortRows(rows, sortA.col, sortA.dir).map((a) =>
      '<tr' + (a.disabled ? ' style="opacity:.55"' : '') + resRow(a.id, a.source) + '>' +
      '<td class="mono" style="word-break:break-all">' + esc(a.source) +
        (a.file && !a.url ? ' ' + pill('file', 'alt') : '') +
        (a.disabled ? ' ' + pill('disabled', 'muted') : '') + '</td>' +
      '<td class="text-end">' + num(a.nameCount) + '</td>' +
      '<td class="text-end">' + num(a.matchCount) + '</td>' +
      '<td>' + (a.certificate ? pill(a.certificate, a.sslVerify ? 'ok' : 'err') : '-') + '</td>' +
      '<td style="color:var(--text-muted)">' + esc(a.comment) + '</td>' +
      '</tr>').join('')
      : '<tr><td colspan="5" class="empty-state">No adlists.</td></tr>';
  }

  function render(): void {
    if (!data) return;
    renderSettings();
    renderStatic();
    renderForwarders();
    renderAdlists();
  }

  function renderSummary(): void {
    if (!data) return;
    const s = data.settings;
    const cache = el('dnsSumCache');
    if (cache) {
      cache.textContent = (s.cacheUsed === null || s.cacheUsed === undefined)
        ? '-' : s.cacheUsed + ' / ' + (s.cacheSize || '?');
    }
    const stat = el('dnsSumStatic');
    if (stat) stat.textContent = String((data.staticEntries || []).length);
    const srv = el('dnsSumServers');
    if (srv) {
      srv.textContent = s.dohEnabled ? 'DoH'
        : (s.servers && s.servers.length) ? 'static'
        : (s.dynamicServers && s.dynamicServers.length) ? 'dynamic' : '-';
    }
    const remote = el('dnsSumRemote');
    if (remote) remote.textContent = s.allowRemoteRequests ? 'allowed' : 'blocked';
  }

  socket.on('dns:update', (d) => {
    if (!d) return;
    data = d;
    renderSummary();
    if (isVisible('dns')) render();
  });

  document.addEventListener('mikrodash:pagechange', (e) => {
    if ((e as CustomEvent).detail === 'dns' && data) render();
  });
  onFeatures(() => { if (data && isVisible('dns')) render(); });

  const ss = el<HTMLInputElement>('dnsStaticSearch');
  if (ss) ss.addEventListener('input', debounce(renderStatic, 150));

  // The row and the Add button both open the resource form. The row carries the
  // `.id` and the identity that resRow() wrote onto it, which is what lets the
  // server refuse a write against a row that has changed underneath.
  mountAdds(socket);
  mountRows(socket);

  // The fleet comparison is its own module: a different source, a different
  // cadence and a different table shape. See its header.
  initDnsFleet(socket, isVisible);
  initDnsTools(socket);
}
