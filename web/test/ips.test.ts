/**
 * THE IPS PAGE (2026-10-27).
 *
 * - Opening the page asks for /api/ips/state for the active router, and the
 *   flows, the count pill and the cards are drawn from the answer.
 * - Every value the sensor reports is escaped: a host name is network data.
 * - Leaving the page stops asking.
 * - The pure helpers: a rule's summary, the action and result tones.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { makeDoc } from './dom-shim.js';

const say = console.log.bind(console);
const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'testdata', '.ips-entry.ts');
fs.writeFileSync(ENTRY, "export * from '../web/src/pages/ips.js';\n");
const OUT = path.join(ROOT, 'testdata', '.ips.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });
const mod = require(OUT);

// THE PURE HELPERS.
assert.strictEqual(mod.ruleSummary({ apps: ['BitTorrent'], categories: [], breeds: [], risks: ['*'], hosts: [],
  clients: ['192.168.88.0/24'] }), 'app BitTorrent · risk * · from 192.168.88.0/24');
assert.strictEqual(mod.ACTION_TONE.block, 'err');
assert.strictEqual(mod.resultTone('refused: ips-protected'), 'warn');
assert.strictEqual(mod.resultTone('listed'), 'err');
assert.ok(mod.statePill({ state: 'connected' }).includes('sensor up'));
say('ok - the IPS helpers summarise a rule and tone its outcomes');

const ids = ['ipsBadge', 'ipsTabs', 'ipsStatePill', 'ipsModePill', 'ipsStatus', 'ipsSeenVal', 'ipsListedVal',
  'ipsListedFoot', 'ipsPacketsVal', 'ipsPacketsFoot', 'ipsTopVal', 'ipsTopFoot', 'ipsFlowFilter', 'ipsFlowMatched',
  'ipsFlowsHead', 'ipsFlowsRows', 'ipsAppsHead', 'ipsAppsRows', 'ipsEventsHead', 'ipsEventsRows', 'ipsListedLoad',
  'ipsListedHead', 'ipsListedRows', 'ipsRulesRows', 'ipsRuleForm', 'ipsRuleFormTitle', 'ipsRuleName', 'ipsRuleAction',
  'ipsRuleApps', 'ipsRuleCategories', 'ipsRuleBreeds', 'ipsRuleRisks', 'ipsRuleHosts', 'ipsRuleClients',
  'ipsRuleTimeout', 'ipsRuleEnabled', 'ipsRuleCancel', 'ipsRuleMsg', 'ipsRuleAddWrap', 'ipsRuleAdd', 'ipsSetupNote',
  'ipsSensorForm', 'ipsSensorAddress', 'ipsSensorEnforce', 'ipsSensorBytes', 'ipsSensorDisk', 'ipsSensorProtected',
  'ipsSensorImage', 'ipsSensorToken', 'ipsSensorDelete', 'ipsSensorMsg', 'ipsScriptShow', 'ipsScriptCopy', 'ipsScript',
  'ipsPlanShow', 'ipsApply', 'ipsRemove', 'ipsPlanMsg', 'ipsPlanWarnings', 'ipsPlanRows',
  'ipsPanel-flows', 'ipsPanel-apps', 'ipsPanel-events', 'ipsPanel-rules', 'ipsPanel-setup'];
const doc = makeDoc(ids, { allowUnknown: ['#ipsTabs [data-ipstab]'] });
global.document = doc;
global.window = { addEventListener: () => {}, setTimeout, clearTimeout, confirm: () => false, alert: () => {} };

const asked: string[] = [];
const state = {
  configured: true, admin: false,
  sensor: { address: '172.31.255.2', enforce: false, sniffBytes: 20000, protected: [], disk: 'usb1', image: '' },
  status: { state: 'connected', message: '', since: 0, sensor: '172.31.255.2:37009', ndpi: '4.14', enforce: false,
    stats: { packets: 4214, bytes: 2580928, flows: 172, active: 3, droppedEvents: 0 }, seen: 2, listed: 0,
    refused: 0, limited: 0, failed: 0 },
  flows: [
    { ts: 2, l4: 'tcp', client: '192.168.88.20', clientPort: 5, server: '203.0.113.7', serverPort: 6881,
      name: 'BitTorrent', app: 'BitTorrent', master: 'Unknown', category: 'Download', breed: 'Acceptable',
      host: '<img src=x>', risks: [], guessed: false, packets: 3, bytes: 400, action: 'block', rule: 'p2p', result: 'monitor' },
    { ts: 1, l4: 'udp', client: '192.168.88.21', clientPort: 6, server: '198.51.100.1', serverPort: 53,
      name: 'DNS', app: 'DNS', master: 'Unknown', category: 'Network', breed: 'Acceptable', host: 'example.com',
      risks: [], guessed: false, packets: 2, bytes: 120, action: '', rule: '', result: '' },
  ],
  apps: [{ name: 'BitTorrent', category: 'Download', flows: 1, bytes: 400 }],
  events: [], rules: [], actions: [], lists: {}, defaults: { sniffBytes: 20000, image: 'img', timeoutMin: 60 },
};
global.fetch = (url: string) => {
  asked.push(url);
  return Promise.resolve({ ok: true, statusText: 'OK', json: () => Promise.resolve(state) });
};

const handlers: Record<string, (d: unknown) => void> = {};
let visible = true;
mod.initIpsPage({ on: (ev: string, fn: (d: unknown) => void) => { handlers[ev] = fn; }, emit: () => {} }, () => visible);
const n = doc.nodes;

(async () => {
  handlers['router:switched']!({ activeId: 'r1' });
  doc.dispatchEvent({ type: 'mikrodash:pagechange', detail: 'ips' });
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(asked.length >= 1 && asked.every((u) => u === '/api/ips/state?router=r1'), 'asked: ' + asked.join(', '));
  assert.strictEqual(n.ipsBadge.textContent, '2', 'the count pill counts the flows in the window');
  assert.strictEqual(n.ipsTopVal.textContent, 'BitTorrent');
  const rows = n.ipsFlowsRows.innerHTML;
  assert.ok(rows.includes('BitTorrent') && rows.includes('monitor'), 'the flows table lacks the decided flow');
  assert.ok(!rows.includes('<img') && rows.includes('&lt;img'), 'a host name reached the page unescaped');
  say('ok - the IPS page draws the state it is given, escaped');

  // LEAVING stops the poll: nothing is asked once another page is shown.
  doc.dispatchEvent({ type: 'mikrodash:pagechange', detail: 'dashboard' });
  visible = false;
  const before = asked.length;
  await new Promise((r) => setTimeout(r, 3200));
  assert.strictEqual(asked.length, before, 'the page went on asking after it was left');
  say('ok - leaving the IPS page stops asking');
  fs.rmSync(OUT, { force: true });
})().catch((e) => { console.error(e); process.exit(1); });
