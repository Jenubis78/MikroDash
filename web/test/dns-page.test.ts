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
fs.writeFileSync(ENTRY, "export { initDnsPage } from '../web/src/pages/dns.js';\n");
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

fs.rmSync(OUT, { force: true });
say('dns-page: all checks passed');
