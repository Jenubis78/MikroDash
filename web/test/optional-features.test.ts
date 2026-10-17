/**
 * THE MONITORING FEATURES' PURE HALVES (Settings -> Features).
 *
 * The decisions the pages make before anything is drawn: how a client's history
 * reads, how an access point is coloured, which CAP is behind, and what the
 * Domain Routing card's headline says.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'testdata', '.of-entry.ts');
fs.writeFileSync(ENTRY,
  "export { historyEvents } from '../web/src/pages/wifi-clients-features.js';\n" +
  "export { apSignal, WEAK_DBM } from '../web/src/pages/wifi-map.js';\n" +
  "export { compareVersions } from '../web/src/pages/caps-versions.js';\n" +
  "export { domainRouteVerdict } from '../web/src/pages/dashboard-card-domainroute.js';\n");
const OUT = path.join(ROOT, 'testdata', '.optional-features.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });

global.document = { getElementById: () => null, querySelectorAll: () => [], querySelector: () => null, addEventListener: () => {} };
global.window = { addEventListener: () => {} };
const { historyEvents, apSignal, WEAK_DBM, compareVersions, domainRouteVerdict } = require(OUT);
const say = console.log.bind(console);

// ── a client's history ──────────────────────────────────────────────────────
const s = (min, ap) => ({ ts: min * 60_000, mac: 'M', iface: 'cap1', ap, ssid: 'Net', signal: -60, txRate: '' });
const ev = historyEvents([s(0, 'Hall'), s(1, 'Hall'), s(2, 'Kitchen'), s(20, 'Kitchen')]).map((e) => e.text);
assert.deepStrictEqual(ev, ['on Hall', 'moved to Kitchen', 'gone for 18 min', 'back on Kitchen']);
say('ok  a history reads as joins, moves and absences');

// ── weak spots ──────────────────────────────────────────────────────────────
assert.strictEqual(apSignal([]), null);
const ap = apSignal([{ signal: -60 }, { signal: -80 }, { signal: '-82' }]);
assert.strictEqual(ap.avg, -74);
assert.strictEqual(ap.weak, 2, 'two clients below ' + WEAK_DBM);
assert.strictEqual(ap.tone, '--accent-warn', 'an average between -65 and -75 is the warning tone');
say('ok  an access point is coloured by its clients\' average signal');

// ── CAP versions ────────────────────────────────────────────────────────────
assert.strictEqual(compareVersions('7.9', '7.24'), -1, 'by number, not by text');
assert.strictEqual(compareVersions('7.24.2', '7.24.2'), 0);
assert.strictEqual(compareVersions('7.25', '7.24.3'), 1);
assert.strictEqual(compareVersions('7.16rc2', '7.16'), -1, 'a release candidate is behind its release');
assert.strictEqual(compareVersions('7.16', '7.16beta4'), 1);
assert.strictEqual(compareVersions('7.16beta4', '7.16rc1'), -1);
assert.strictEqual(compareVersions('7.16rc2 (testing)', '7.16rc10'), -1);
assert.strictEqual(compareVersions('7.17beta1', '7.16.2'), 1);
say('ok  a CAP is behind by version number');

// ── the Domain Routing card's headline ──────────────────────────────────────
const base = { routerId: 'r1', list: 'to_vpn', feeding: 1265, entries: 300, rules: [], routes: [],
  ok: true, why: '', error: '', withheld: [], ts: 1 };
assert.strictEqual(domainRouteVerdict(base).word, 'routed');
assert.strictEqual(domainRouteVerdict({ ...base, feeding: 0 }).word, 'not used',
  'a router whose entries feed no list is not shown as broken');
const down = domainRouteVerdict({ ...base, ok: false, why: 'No active route in vpn' });
assert.ok(down.word === 'down' && down.text.includes('vpn'));
const hidden = domainRouteVerdict({ ...base, ok: false, why: '', withheld: ['Firewall', 'Routing'] });
assert.ok(hidden.word === 'down' && !hidden.text.includes('route in'), 'the reason is withheld with the tables: ' + hidden.text);
say('ok  the card says routed, down or not used, and keeps the reason from a viewer without the pages behind it');

fs.rmSync(OUT, { force: true });
say('optional-features: all checks passed');
