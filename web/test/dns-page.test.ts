/**
 * THE DNS PAGE: STATIC ENTRIES, FORWARDERS AND ADLISTS (2026-10-13).
 *
 * A FWD entry is usually written to put a domain's answers on an address list,
 * often with no forward-to of its own, and the table showed neither: no
 * address-list column, and a blank where the value goes. Forwarders and
 * adlists had no card at all. This boots the real module, feeds it a
 * `dns:update` and reads what the tables say.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { makeDoc } from './dom-shim.js';

const say = console.log.bind(console);
const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');

const ENTRY = path.join(ROOT, 'testdata', '.dnspage-entry.ts');
fs.writeFileSync(ENTRY, "export { initDnsPage } from '../web/src/pages/dns.js';\n" +
  "export { buildRows } from '../web/src/pages/dns-fleet.js';\n" +
  "export { heldElsewhere } from '../web/src/pages/dns-fleet.js';\n" +
  "export { rscLine, rscValue, csvCell, jobProgress } from '../web/src/pages/dns-bulk.js';\n");
const OUT = path.join(ROOT, 'testdata', '.dnspage.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });

const IDS = [
  'dnsSettingsBody', 'dnsSettingsEdit', 'dnsSumCache', 'dnsSumStatic', 'dnsSumServers', 'dnsSumRemote',
  'dnsStaticCard', 'dnsStaticSearch', 'dnsStaticThead', 'dnsStaticBadge', 'dnsStaticTable',
  'dnsFwdCard', 'dnsFwdBadge', 'dnsFwdThead', 'dnsFwdTable',
  'dnsAdlistCard', 'dnsAdlistBadge', 'dnsAdlistThead', 'dnsAdlistTable',
  'dnsFleetCard', 'dnsScopeOne', 'dnsScopeFleet', 'dnsFleetPick', 'dnsFleetThead', 'dnsFleetTable',
  'dnsFleetBadge', 'dnsFleetNote', 'dnsFleetAddBtn', 'dnsFleetReload', 'dnsFleetSyncAll',
  // Settings -> Features: the cache browser and the route trace.
  'dnsCacheCard', 'dnsCacheBadge', 'dnsCacheNote', 'dnsCacheSearch', 'dnsCacheRead', 'dnsCacheThead',
  'dnsCacheTable', 'dnsTraceCard', 'dnsTraceName', 'dnsTraceGo', 'dnsTraceOut',
  // Bulk edit and export, the fleet sync and the domain lists.
  'dnsStaticCols', 'dnsBulkBar', 'dnsBulkCount', 'dnsBulkField', 'dnsBulkValue', 'dnsBulkApply',
  'dnsBulkEnable', 'dnsBulkDisable', 'dnsBulkRemove', 'dnsBulkClear', 'dnsBulkNote', 'dnsExportTools',
  'dnsExportRsc', 'dnsExportCsv', 'dnsFleetSyncTools', 'dnsFleetRef', 'dnsFleetRemoveExtra', 'dnsFleetSyncRef',
  'dnsListsCard', 'dnsListsBadge', 'dnsListsNote', 'dnsListAdd', 'dnsListForm', 'dnsListsThead', 'dnsListsTable',
];

const SETTINGS = {
  servers: ['198.51.100.53'], dynamicServers: [], dohEnabled: false, dohUrl: '', dohVerifyCert: false,
  dohMaxServerConnections: 5, dohMaxConcurrentQueries: 50, dohTimeout: '5s', allowRemoteRequests: true,
  cacheSize: 8192, cacheUsed: 100, cacheMaxTtl: '1w', maxUdpPacketSize: 4096, maxConcurrentQueries: 100,
  queryServerTimeout: '2s', queryTotalTimeout: '10s', mdnsRepeatIfaces: [], vrf: 'main',
  addressListExtraTime: '4h',
};

function entry(over) {
  return Object.assign({
    id: '*1', name: '', regexp: '', address: '', type: 'A', ttl: '1d', disabled: false, comment: '',
    addressList: '', matchSubdomain: false, dynamic: false,
  }, over);
}

function boot() {
  const doc = makeDoc(IDS, { allowUnknown: [
    // The shared resource dialog, which lives in the shell rather than on this page.
    'res_previewBtn', 'res_save', 'res_dup', 'res_delete', '[data-modal-close="resModal"]', 'resModal',
    '[data-res-add]'] });
  const handlers = {};
  const socket = { on: (ev, fn) => { handlers[ev] = fn; }, emit: () => {} };
  const prevDoc = global.document;
  const prevWin = global.window;
  global.document = doc;
  global.window = { addEventListener: () => {}, setTimeout, clearTimeout };
  const { initDnsPage } = require(OUT);
  initDnsPage(socket, () => true);
  return {
    doc,
    handlers,
    send: (over) => handlers['dns:update'](Object.assign({
      ts: 1, pollMs: 10000, settings: SETTINGS, available: true,
      staticEntries: [], forwarders: [], forwardersAvailable: true, adlists: [], adlistsAvailable: true,
    }, over)),
    html: (id) => String(doc.nodes[id].innerHTML),
    restore: () => { global.document = prevDoc; global.window = prevWin; },
  };
}

// ── 1. a FWD entry shows its address list, and a missing forward-to says where it goes
{
  const { send, html, doc, restore } = boot();
  send({ staticEntries: [
    entry({ id: '*1', name: 'example.com', type: 'FWD', addressList: 'to_vpn_FWD', matchSubdomain: true, ttl: '' }),
    entry({ id: '*2', name: 'corp.example', type: 'FWD', address: 'zfwdentry', addressList: 'to_vpn_FWD' }),
    entry({ id: '*3', regexp: '^ads[0-9]*\\.', address: '0.0.0.0' }),
    entry({ id: '*4', name: 'pc.lan', address: '198.51.100.20', dynamic: true }),
  ] });
  const body = html('dnsStaticTable');
  const head = html('dnsStaticThead');
  assert.ok(head.includes('Address List'), 'the table has no Address List column:\n' + head);
  assert.strictEqual((body.match(/>to_vpn_FWD</g) || []).length, 2, 'the address list is not in the rows:\n' + body);
  assert.ok(body.includes('>default servers<'), 'a FWD entry with no forward-to shows a blank value:\n' + body);
  assert.ok(body.includes('>zfwdentry<'), 'a forward-to naming a forwarder is not shown:\n' + body);
  assert.ok(body.includes('+sub'), 'match-subdomain is not marked:\n' + body);
  assert.ok(body.includes('>regexp<') && body.includes('>dynamic<'), 'regexp or dynamic is not marked:\n' + body);
  // A regexp entry has no name: its regexp is the identity the server finds the row by.
  assert.ok(body.includes('data-id="*3" data-identity="^ads[0-9]*\\."'), 'a regexp entry carries no identity:\n' + body);
  assert.ok(String(doc.nodes['dnsSettingsBody'].innerHTML).includes('4h'),
    'the resolver card does not show the address list extra time');
  assert.strictEqual(doc.nodes['dnsCacheCard'].style.display, 'none', 'the cache card shows with its feature off');
  assert.strictEqual(doc.nodes['dnsTraceCard'].style.display, 'none', 'the trace card shows with its feature off');
  restore();
  say('ok  a FWD entry shows its address list, its forwarder, or the default servers');
}

// ── 2. the forwarder and adlist cards follow the router, and say who uses a forwarder
{
  const { send, html, doc, restore } = boot();
  send({ forwardersAvailable: false, adlistsAvailable: false });
  assert.strictEqual(doc.nodes['dnsFwdCard'].style.display, 'none', 'a router without forwarders shows the card');
  assert.strictEqual(doc.nodes['dnsAdlistCard'].style.display, 'none', 'a router without adlists shows the card');

  send({
    forwarders: [{ id: '*A', name: 'zfwdentry', dnsServers: ['198.51.100.7'], dohServers: [],
      verifyDohCert: true, comment: 'vpn exit', disabled: false, usedBy: 1205 }],
    adlists: [
      { id: '*B', url: 'https://example.com/hosts.txt', file: '', sslVerify: false, comment: '', disabled: false,
        nameCount: 1200, matchCount: 7 },
      { id: '*C', url: '', file: 'hosts.txt', sslVerify: true, comment: '', disabled: true,
        nameCount: null, matchCount: null },
    ],
  });
  const fwd = html('dnsFwdTable');
  const ads = html('dnsAdlistTable');
  const heads = html('dnsFwdThead') + html('dnsAdlistThead');
  restore();
  assert.strictEqual(doc.nodes['dnsFwdCard'].style.display, '', 'the forwarder card stayed hidden');
  assert.ok(fwd.includes('data-id="*A"') && fwd.includes('1205 entries') && fwd.includes('>vpn exit<'),
    'the forwarder row is wrong:\n' + fwd);
  assert.ok(ads.includes('data-id="*B"') && ads.includes('pill-err">not verified<'), 'the adlist row is wrong:\n' + ads);
  assert.ok(ads.includes('data-identity="hosts.txt"') && ads.includes('>disabled<'),
    'a file adlist carries no identity, or a disabled one is not marked:\n' + ads);
  assert.strictEqual((heads.match(/th-sort/g) || []).length, 10, 'a column of the two tables does not sort:\n' + heads);
  say('ok  forwarders and adlists render where the router has them, and only there');
}

// ── 3. the Add dialog says which compared routers already hold the record
{
  const { heldElsewhere } = require(OUT);
  const fwd = (name, forwardTo) => ({ name, regexp: '', type: 'FWD', values: { name, type: 'FWD', forwardTo } });
  const routers = [
    { id: 'here', label: 'here', ok: true, error: '', entries: [fwd('example.com', 'zfwdentry')] },
    { id: 'b', label: 'b', ok: true, error: '', entries: [fwd('Example.com', 'zfwdentry')] },
    { id: 'c', label: 'c', ok: true, error: '', entries: [fwd('example.com', 'yandex')] },
    { id: 'd', label: 'd', ok: true, error: '', entries: [fwd('other.com', 'zfwdentry')] },
    { id: 'e', label: 'e', ok: false, error: 'unreachable', entries: [] },
  ];
  const held = heldElsewhere(routers, 'here', { name: 'example.com', regexp: '', type: 'FWD', value: 'zfwdentry' });
  assert.deepStrictEqual(held, { same: ['b'], differ: ['c'] },
    'the record is on b, on c with another forwarder, and nowhere else: ' + JSON.stringify(held));
  assert.deepStrictEqual(heldElsewhere(routers, 'here', { name: '', regexp: '', type: 'FWD', value: '' }),
    { same: [], differ: [] }, 'an empty form matched records');
  const txt = (id, text) => ({ id, label: id, ok: true, error: '',
    entries: [{ name: 'v.example', regexp: '', type: 'TXT', values: { text } }] });
  assert.deepStrictEqual(
    heldElsewhere([txt('x', 'Token-AbC'), txt('y', 'token-abc')], 'here',
      { name: 'v.example', regexp: '', type: 'TXT', value: 'Token-AbC' }),
    { same: ['x'], differ: ['y'] }, 'a TXT value in another case is the same value');
  say('ok  the dialog names the routers that already hold the record, and those with another value');
}

// ── 4. an export is what /ip dns static add takes, and a CSV cell never runs as a formula
{
  const { rscLine, rscValue, csvCell, jobProgress } = require(OUT);
  assert.strictEqual(rscValue('to_vpn_FWD'), 'to_vpn_FWD');
  assert.strictEqual(rscValue('two words'), '"two words"');
  assert.strictEqual(rscValue('^a\\.b$'), '"^a\\\\.b\\$"', 'a regexp keeps its backslash and dollar through the script');
  assert.strictEqual(rscValue('v=spf1\nadd name=evil'), '"v=spf1\\nadd name=evil"', 'a line break stays in its value');
  assert.strictEqual(rscValue('a\r\tb'), '"a\\r\\tb"');
  assert.strictEqual(rscValue('a\x00b\x1fc\x7fd'), '"a\\00b\\1Fc\\7Fd"', 'the other control characters are \\XX');
  const line = rscLine({ name: 'x.example', type: 'TXT', text: 'one\n/system reset-configuration', comment: 'a\nb' });
  assert.ok(!line.includes('\n') && !line.includes('\r'), 'an export line is more than one line: ' + JSON.stringify(line));
  assert.strictEqual(
    rscLine({ name: 'example.com', type: 'FWD', forwardTo: 'zfwdentry', addressList: 'to_vpn_FWD',
      matchSubdomain: true, ttl: '1d', disabled: false, comment: 'by hand' }),
    'add name=example.com type=FWD forward-to=zfwdentry address-list=to_vpn_FWD match-subdomain=yes comment="by hand"');
  for (const [raw, want] of [['=HYPERLINK("x")', '"\'=HYPERLINK(""x"")"'], ['+1', "'+1"], ['-1', "'-1"],
    ['@SUM(A1)', "'@SUM(A1)"], ['plain, text', '"plain, text"'], ['v=spf1 -all', 'v=spf1 -all']]) {
    assert.strictEqual(csvCell(raw), want, 'csvCell(' + raw + ')');
  }
  assert.ok(jobProgress({ done: 3, total: 9, waitingUntil: 10_000 }, 1_000).includes('waiting 9 s for the write limit'),
    'a job held by the write limit does not say so');
  say('ok  an export line is what add takes, a CSV cell never starts a formula, and a waiting job says why');
}

// ── the comparison lines a name up without case, and a round-robin pair by value
{
  const { buildRows } = require(OUT);
  const rec = (id, name, address) => ({ id, name, regexp: '', address, type: 'A', ttl: '', disabled: false,
    comment: '', addressList: '', matchSubdomain: false, dynamic: false, values: {} });
  const router = (id, entries) => ({ id, label: id, ok: true, error: '', entries });
  const same = buildRows([router('a', [rec('*1', 'MDPROBE.test', '198.51.100.1')]),
    router('b', [rec('*2', 'mdprobe.test', '198.51.100.1')])]);
  assert.strictEqual(same.length, 1, 'a name in another case is a second line: ' + JSON.stringify(same.map((r) => r.name)));
  assert.deepStrictEqual(same[0].missing, [], 'a case variant is offered as a copy');
  assert.strictEqual(same[0].byValue, false);

  const pair = buildRows([router('a', [rec('*1', 'www.lan', '198.51.100.1'), rec('*2', 'WWW.lan', '198.51.100.2')]),
    router('b', [rec('*3', 'www.lan', '198.51.100.1')])]);
  assert.strictEqual(pair.length, 2, 'two records of one name are not two lines');
  assert.ok(pair.every((r) => r.byValue), 'a round-robin pair is not lined up by value');
  assert.deepStrictEqual(pair.filter((r) => r.missing.length).map((r) => r.missing), [['b']],
    'only the second address is missing on b');
  say('ok  names line up without case, a round-robin pair by value');
}

// ── 6. a slow read of the router that was selected is not drawn under the next one
{
  const { doc, handlers, restore } = boot();
  const pending = [];
  const prevFetch = global.fetch;
  global.fetch = (url) => new Promise((resolve) => pending.push({ url, resolve }));
  const answer = (rows) => ({ ok: true, statusText: '', json: () => Promise.resolve({ total: rows.length,
    cached: rows.length, rows, steps: [], matches: [], answering: [] }) });
  handlers['router:active']({ activeId: 'A' });
  doc.nodes['dnsCacheRead'].fire('click');
  doc.nodes['dnsTraceName'].value = 'www.example.com';
  doc.nodes['dnsTraceGo'].fire('click');
  assert.strictEqual(pending.length, 2, 'the two reads were not started: ' + pending.length);
  handlers['router:switched']({ activeId: 'B' });
  pending[0].resolve(answer([{ name: 'from-a.example', type: 'A', data: '198.51.100.1', ttl: '1m' }]));
  pending[1].resolve({ ok: true, statusText: '', json: () => Promise.resolve({ name: 'www.example.com', matches: [],
    answering: [], steps: [{ step: 'Static entry', state: 'ok', text: 'from A' }] }) });
  setTimeout(() => {
    const table = String(doc.nodes['dnsCacheTable'].innerHTML);
    global.fetch = prevFetch;
    restore();
    assert.ok(!table.includes('from-a.example'), 'router A\'s cache was drawn under router B:\n' + table);
    assert.ok(!String(doc.nodes['dnsTraceOut'].innerHTML).includes('from A'),
      'router A\'s trace was drawn under router B');
    say('ok  a read of the router that was selected is dropped when another is');
    fs.rmSync(OUT, { force: true });
    say('dns-page: all checks passed');
  }, 20);
}
