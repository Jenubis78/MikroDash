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
  clients: ['192.168.88.0/24'], countries: ['CN'] }), 'app BitTorrent · risk * · from 192.168.88.0/24 · country CN');
assert.strictEqual(mod.ACTION_TONE.block, 'err');
assert.strictEqual(mod.resultTone('refused: ips-protected'), 'warn');
assert.strictEqual(mod.resultTone('listed'), 'err');
assert.ok(mod.statePill({ state: 'connected' }).includes('sensor up'));
assert.strictEqual(mod.networkLabel({ interface: 'vlan11', prefix: '192.168.11.0/24', gateway: '192.168.11.1', bridge: 'bridge',
  vlan: 11, why: '' }), 'vlan11 - 192.168.11.0/24 (VLAN 11 on bridge)');
assert.ok(mod.networkLabel({ interface: 'ether1', prefix: '203.0.113.0/30', gateway: '', bridge: '', vlan: 0,
  why: 'ether1 is not a bridge' }).endsWith('cannot be joined: ether1 is not a bridge'));
const cat = { ndpi: '4.14', apps: [{ name: 'NetFlix', category: 'Video', breed: 'Fun' },
  { name: 'BitTorrent', category: 'Download', breed: 'Acceptable' }, { name: 'YouTube', category: 'Video', breed: 'Fun' }],
categories: ['Video', 'Download'], breeds: ['Safe', 'Fun'],
risks: [{ name: 'Known Proto on Non Std Port', severity: 'Medium' }, { name: 'Self-signed Cert', severity: 'High' }],
countries: [{ iso: 'CN', name: 'China' }, { iso: 'FR', name: 'France' }] };
const apps = mod.pickHtml('apps', ['NetFlix', 'old<one>'], cat);
assert.ok(apps.includes('data-ipsunpick="apps" data-v="NetFlix"') && apps.includes('old&lt;one&gt;'),
  'the chosen values, a value the catalogue does not name among them, are chips, escaped');
assert.ok(apps.includes('<optgroup label="Video"><option value="YouTube">') && !apps.includes('<option value="NetFlix">'),
  'applications are grouped by category, and a chosen one is not offered again');
const risks = mod.pickHtml('risks', [], cat);
assert.ok(risks.includes('<option value="*">Any risk</option>'), 'any risk is offered first');
assert.ok(mod.pickHtml('breeds', [], null).includes(' disabled'), 'with no catalogue yet the list waits, disabled');
assert.ok(risks.includes('Self-signed Cert (High)'), 'a risk is offered with its severity');
const countries = mod.pickHtml('countries', ['CN'], cat);
assert.ok(countries.includes('<option value="FR">France (FR)</option>') && !countries.includes('value="CN"') &&
  countries.includes('data-v="CN"'), 'countries by name, the chosen one a chip');
assert.ok(mod.pickHtml('countries', [], { ...cat, countries: [] }).includes('No geo database'), 'no geo database is said');
assert.ok(mod.flagged('203.0.113.9', 'CN').includes('🇨🇳') && mod.flagged('192.168.1.1', '') === '192.168.1.1');
assert.strictEqual(mod.severityRank('High'), 3);
assert.strictEqual(mod.severityTone('Severe'), 'err');
assert.strictEqual(mod.severityTone('Medium'), 'warn');
assert.ok(mod.riskPill('Medium', ['a', '<b>']).includes('Medium · 2') && mod.riskPill('Medium', ['a', '<b>']).includes('&lt;b&gt;'));
assert.strictEqual(mod.riskPill('', []), '-');
const flow = { app: 'BitTorrent', host: '', name: 'BitTorrent' };
assert.deepStrictEqual([mod.blockRuleFor(flow).apps, mod.blockRuleFor(flow).action], [['BitTorrent'], 'block']);
assert.deepStrictEqual(mod.blockRuleFor({ app: 'Unknown', host: 'www.example.com' }).hosts, ['example.com']);
assert.strictEqual(mod.blockRuleFor({ app: 'Unknown', host: '' }), null);
say('ok - the IPS helpers summarise a rule and tone its outcomes');

const ids = ['ipsBadge', 'ipsTabs', 'ipsStatePill', 'ipsModePill', 'ipsStatus', 'ipsSeenVal', 'ipsListedVal',
  'ipsListedFoot', 'ipsPacketsVal', 'ipsPacketsFoot', 'ipsTopVal', 'ipsTopFoot', 'ipsFlowFilter', 'ipsFlowMatched',
  'ipsFlowRisky', 'ipsFlowPause', 'ipsRisksHead', 'ipsRisksRows', 'ipsPanel-risks', 'ipsFlowsHead', 'ipsFlowsRows', 'ipsAppsHead', 'ipsAppsRows', 'ipsEventsHead', 'ipsEventsRows', 'ipsListedLoad',
  'ipsListedHead', 'ipsListedRows', 'ipsRulesRows', 'ipsRuleForm', 'ipsRuleFormTitle', 'ipsRuleName', 'ipsRuleAction',
  'ipsRuleAppsPick', 'ipsRuleCategoriesPick', 'ipsRuleBreedsPick', 'ipsRuleRisksPick', 'ipsRuleCountriesPick', 'ipsRuleHosts', 'ipsRuleClients',
  'ipsRuleTimeout', 'ipsRuleEnabled', 'ipsRuleCancel', 'ipsRuleMsg', 'ipsRuleAddWrap', 'ipsRuleAdd', 'ipsSetupNote',
  'ipsSensorForm', 'ipsSensorAddress', 'ipsSensorEnforce', 'ipsSensorBytes', 'ipsSensorInspect', 'ipsSensorBytesField', 'ipsSensorInspectHelp', 'ipsSensorDisk', 'ipsSensorProtected',
  'ipsSensorImage', 'ipsSensorNetwork', 'ipsSensorNetworkHelp', 'ipsSensorDhcp', 'ipsSensorAddressField', 'ipsSensorToken', 'ipsSensorDelete', 'ipsSensorMsg', 'ipsScriptShow', 'ipsScriptCopy', 'ipsScript',
  'ipsPlanShow', 'ipsApply', 'ipsRemove', 'ipsGeoForm', 'ipsGeoApply', 'ipsGeoRemove', 'ipsPlanMsg', 'ipsPlanWarnings', 'ipsPlanRows',
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
      host: '<img src=x>', risks: ['Known Proto on Non Std Port'], guessed: false, packets: 3, bytes: 400, action: 'block',
      rule: 'p2p', result: 'monitor', severity: 'Medium' },
    { ts: 1, l4: 'udp', client: '192.168.88.21', clientPort: 6, server: '198.51.100.1', serverPort: 53,
      name: 'DNS', app: 'DNS', master: 'Unknown', category: 'Network', breed: 'Acceptable', host: 'example.com',
      risks: [], guessed: false, packets: 2, bytes: 120, action: '', rule: '', result: '', severity: '' },
  ],
  apps: [{ name: 'BitTorrent', category: 'Download', flows: 1, bytes: 400 }],
  risks: [{ name: 'Known Proto on Non Std Port', severity: 'Medium', flows: 1, clients: 1, apps: ['BitTorrent'],
    lastTs: 2, lastClient: '192.168.88.20', lastServer: '203.0.113.7' }],
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
  assert.ok(rows.includes('Medium'), 'the flow shows its risk severity');

  say('ok - the IPS page draws the state it is given, escaped');

  // PAUSE keeps the window it had while new flows arrive, and counts them.
  n.ipsFlowPause.fire('click');
  state.flows = [{ ...state.flows[1], ts: 9, client: '192.168.88.99', severity: '' }, ...state.flows];
  await new Promise((r) => setTimeout(r, 3300));
  assert.ok(!n.ipsFlowsRows.innerHTML.includes('192.168.88.99'), 'a paused table took a new flow');
  assert.strictEqual(n.ipsFlowPause.textContent, 'Paused · 1 new');
  n.ipsFlowPause.fire('click');
  assert.ok(n.ipsFlowsRows.innerHTML.includes('192.168.88.99'), 'resuming shows the flows that arrived');
  say('ok - pausing freezes the flows table and says what arrived');

  // GEOFENCING: a running apply says how far it is, a refused one names what
  // it would have cut off, a finished one says nothing here.
  const job = { running: true, remove: false, phase: 'adding entries', done: 120, total: 3000, error: '', conflicts: [] as string[] };
  assert.strictEqual(mod.geoJobLine(job), 'Applying: adding entries 120 / 3000…');
  assert.strictEqual(mod.geoJobLine({ ...job, running: false, error: 'these countries hold addresses the router is reached from',
    conflicts: ['198.51.100.7 (FR)'] }), 'Stopped: these countries hold addresses the router is reached from (198.51.100.7 (FR))');
  assert.strictEqual(mod.geoJobLine({ ...job, running: false }), '');
  say('ok - a geofencing apply reads as its progress or why it stopped');
  // The question before writing names what will be dropped: the blacklist
  // less the whitelist, or every country but the whitelist.
  assert.strictEqual(mod.geoApplyQuestion(false, 'block', 'in', ['FR'], ['CN', 'FR']),
    'Drop new connections from CN? (FR stays: whitelisted.)');
  assert.ok(mod.geoApplyQuestion(false, 'allow', 'both', ['FR', 'BE'], []).startsWith(
    'Drop new connections to and from every country but FR, BE'));
  assert.ok(mod.geoApplyQuestion(false, 'block', 'in', ['FR'], ['FR']).startsWith('Remove'),
    'a blacklist the whitelist empties is a removal');
  say('ok - geofencing asks about what it will drop, never the whitelist');

  // LEAVING stops the poll: nothing is asked once another page is shown.
  doc.dispatchEvent({ type: 'mikrodash:pagechange', detail: 'dashboard' });
  visible = false;
  const before = asked.length;
  await new Promise((r) => setTimeout(r, 3200));
  assert.strictEqual(asked.length, before, 'the page went on asking after it was left');
  say('ok - leaving the IPS page stops asking');
  fs.rmSync(OUT, { force: true });
})().catch((e) => { console.error(e); process.exit(1); });
