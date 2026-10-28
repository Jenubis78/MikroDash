/**
 * THE TRAFFIC ANALYSIS PAGE (2026-10-28).
 *
 * - The pure helpers: a minute's bytes as a rate, a country's label, the
 *   stacked series with no holes, the collector's pill.
 * - Opening the page asks /api/traffic/state for the active router and draws
 *   the last minute, escaped; leaving it stops asking.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { makeDoc } from './dom-shim.js';

const say = console.log.bind(console);
const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'testdata', '.traffic-entry.ts');
fs.writeFileSync(ENTRY, "export * from '../web/src/pages/traffic-analysis.js';\n");
const OUT = path.join(ROOT, 'testdata', '.traffic.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });
// eslint-disable-next-line @typescript-eslint/no-var-requires
const mod = require(OUT);

// THE PURE HELPERS.
assert.strictEqual(mod.spanRate(7_500_000, 60), 1_000_000, '7.5 MB in a minute is 1 Mbit/s');
assert.strictEqual(mod.spanRate(3_750_000, 30), 1_000_000, 'and 3.75 MB in 30 s too');
assert.strictEqual(mod.spanLabel(30), 'last 30 s');
assert.strictEqual(mod.spanLabel(60), 'last minute');
assert.ok(mod.statePill({ enabled: true, source: 'sensor', lastAt: Date.now() }).includes('sensor live'));
assert.strictEqual(mod.keyLabel('country', 'FR'), '🇫🇷 FR');
assert.strictEqual(mod.keyLabel('country', ''), 'Unknown');
assert.strictEqual(mod.keyLabel('app', 'YouTube'), 'YouTube');
assert.strictEqual(mod.protoName(17), 'udp');
// Three one-minute steps; YouTube has none in the middle one, which is a 0,
// not a hole, and Other comes last.
const t0 = Date.UTC(2026, 9, 28, 14, 0, 0);
const iso = (ms: number): string => new Date(ms).toISOString();
const s = mod.seriesDatasets([
  { ts: iso(t0), key: 'YouTube', rx: 60, tx: 0 },
  { ts: iso(t0 + 120000), key: 'YouTube', rx: 0, tx: 120 },
  { ts: iso(t0 + 60000), key: 'Other', rx: 6, tx: 0 },
], ['YouTube'], t0, t0 + 180000, 60);
assert.deepStrictEqual(s.labels, [t0, t0 + 60000, t0 + 120000]);
assert.deepStrictEqual(s.sets.map((x: { key: string }) => x.key), ['YouTube', 'Other']);
assert.deepStrictEqual(s.sets[0].data, [8, 0, 16], 'bits per second per step');
assert.deepStrictEqual(s.sets[1].data, [0, 0.8, 0]);
assert.ok(mod.statePill({ enabled: false }).includes('not set up'));
assert.ok(mod.statePill({ enabled: false }, true).includes('interrupted'), 'a router handed to the sensor and not back says so');
assert.ok(mod.statePill({ enabled: true, listening: true, lastAt: Date.now() }).includes('receiving'));
assert.ok(mod.statePill({ enabled: true, listening: false }).includes('not listening'));
say('ok - the Traffic Analysis helpers rate, label and stack');

const ids = ['taBadge', 'taTabs', 'taRxFoot', 'taTxFoot', 'taRecordsLabel', 'taStatePill', 'taBackendPill', 'taStatus', 'taRxVal', 'taTxVal', 'taCoverageVal',
  'taCoverageFoot', 'taRecordsVal', 'taRecordsFoot', 'taLiveDims', 'taLiveAt', 'taLiveHead', 'taLiveRows',
  'taHistDim', 'taHistRange', 'taHistFilters', 'taHistMsg', 'taHistChart', 'taHistHead', 'taHistRows',
  'taFlowHost', 'taFlowRemote', 'taFlowApp', 'taFlowCountry', 'taFlowRange', 'taFlowSearch', 'taFlowMsg',
  'taFlowsHead', 'taFlowsRows', 'taSetupNote', 'taSettingsForm', 'taBackend', 'taPort', 'taCollector', 'taChUrl',
  'taChUser', 'taChPassword', 'taChPasswordHelp', 'taChDatabase', 'taFlowDays', 'taSettingsMsg', 'taRouterForm',
  'taInterfaces', 'taRouterMsg', 'taPlanShow', 'taApply', 'taRemove', 'taPlanMsg', 'taPlanWarnings', 'taPlanRows',
  'taPanel-live', 'taPanel-history', 'taPanel-flows', 'taPanel-setup'];
const doc = makeDoc(ids, { allowUnknown: ['#taTabs [data-tatab]', '#taLiveDims [data-tadim]', '.ta-ch', '.ta-days', '#taBackend option[value="stack"]'] });
global.document = doc;
global.window = { addEventListener: () => {}, setTimeout, clearTimeout, confirm: () => false, alert: () => {} };

const asked: string[] = [];
const state = {
  router: { enabled: true, interfaces: '', appliedAt: 1, result: 'applied' },
  status: { enabled: true, listening: true, port: 2055, listen: '', backend: 'sqlite', storeError: '', records: 1234,
    lost: 0, unknown: 0, lastAt: Date.now(), coverage: 0.9, conns: 40, strays: 0, addresses: 3, source: 'ipfix', ignored: 0 },
  live: {
    app: [{ key: 'YouTube', rx: 7_500_000, tx: 750_000, flows: 3 }, { key: '<b>x</b>', rx: 10, tx: 10, flows: 1 }],
    category: [], host: [], country: [{ key: 'US', rx: 7_500_000, tx: 0, flows: 3 }],
  },
  liveAt: Date.now() - 60000, liveSeconds: 60, admin: false,
};
global.fetch = (url: string) => {
  asked.push(url);
  return Promise.resolve({ ok: true, statusText: 'OK', json: () => Promise.resolve(state) });
};

const handlers: Record<string, (d: unknown) => void> = {};
let visible = true;
mod.initTrafficAnalysisPage({ on: (ev: string, fn: (d: unknown) => void) => { handlers[ev] = fn; }, emit: () => {} }, () => visible);
const n = doc.nodes;

(async () => {
  handlers['router:switched']!({ activeId: 'r1' });
  doc.dispatchEvent({ type: 'mikrodash:pagechange', detail: 'traffic-analysis' });
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(asked.length >= 1 && asked.every((u) => u === '/api/traffic/state?router=r1'), 'asked: ' + asked.join(', '));
  assert.strictEqual(n.taBadge.textContent, '2', 'the count pill counts the applications of the last minute');
  assert.ok(n.taRxVal.textContent.includes('1'), 'download: ' + n.taRxVal.textContent);
  assert.strictEqual(n.taCoverageVal.textContent, '90 %');
  const rows = n.taLiveRows.innerHTML;
  assert.ok(rows.includes('YouTube'), 'the live table lacks the application');
  assert.ok(!rows.includes('<b>x') && rows.includes('&lt;b&gt;'), 'a key reached the page unescaped');
  say('ok - the Traffic Analysis page draws the last minute, escaped');

  doc.dispatchEvent({ type: 'mikrodash:pagechange', detail: 'dashboard' });
  visible = false;
  const before = asked.length;
  await new Promise((r) => setTimeout(r, 5300));
  assert.strictEqual(asked.length, before, 'the page went on asking after it was left');
  say('ok - leaving the Traffic Analysis page stops asking');
  fs.rmSync(OUT, { force: true });
})().catch((e) => { console.error(e); process.exit(1); });
