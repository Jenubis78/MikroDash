/**
 * A ROUTER SWITCH LANDS THE TRAFFIC GRAPH ON THE NEW ROUTER'S WAN.
 *
 * Found alongside issue #158. `forgetRouter` cleared the interface tiles on a
 * switch and left the traffic picker holding the previous router's interfaces.
 * Two orders of arrival, two wrong results:
 *
 *   NAMES FIRST    the picker's old selection is missing from the new names, so
 *                  it picked the first one and sent `traffic:select`, overriding
 *                  the WAN the server had subscribed this viewer to. The graph
 *                  really showed the wrong interface.
 *   HISTORY FIRST  the WAN history set the picker to a name not among the old
 *                  options, so it went blank, and the names then displayed the
 *                  first interface while the chart drew the WAN.
 *
 * Both were seen against CHR Test with its WAN set to `internal`, switching
 * from the hAP AX3. The control keeps the behaviour the picker had for a
 * reason: on ONE router, an interface that goes down moves the graph to the
 * first live one.
 */
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const say = console.log.bind(console);
const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');

const ENTRY = path.join(ROOT, 'testdata', '.router-switch-picker-entry.ts');
fs.writeFileSync(ENTRY,
  "export { initInterfacesPage, resetInterfacesPage } from '../web/src/pages/interfaces.js';\n" +
  "export { onTrafficHistory, resetTraffic } from '../web/src/pages/dashboard-traffic.js';\n");
const OUT = path.join(ROOT, 'testdata', '.router-switch-picker.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });

// ── the shim ────────────────────────────────────────────────────────────────
const g = globalThis as any;
const els = new Map<string, any>();
function fakeEl(id: string): any {
  return {
    id, style: {} as Record<string, string>, dataset: {} as Record<string, string>,
    value: '', options: [], innerHTML: '', _t: '',
    set textContent(v: unknown) { this._t = String(v); },
    get textContent() { return this._t; },
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, closest: () => null, querySelector: () => null,
    querySelectorAll: () => [], getAttribute: () => null, setAttribute() {},
  };
}
// A SELECT THAT BEHAVES LIKE ONE, which is the whole of this bug: a value not
// among the options reads back empty, and the first option appended is
// selected.
function fakeSelect(id: string): any {
  const s: any = fakeEl(id);
  let opts: { value: string }[] = [];
  let v = '';
  Object.defineProperty(s, 'options', { get: () => opts });
  Object.defineProperty(s, 'innerHTML', {
    get: () => '', set: (h: string) => { if (h === '') { opts = []; v = ''; } } });
  Object.defineProperty(s, 'value', {
    get: () => v, set: (x: string) => { v = opts.some((o) => o.value === x) ? x : ''; } });
  s.appendChild = (o: { value: string }) => { opts.push(o); if (opts.length === 1) v = o.value; };
  return s;
}
els.set('ifaceSelect', fakeSelect('ifaceSelect'));
g.document = {
  hidden: false,
  body: { classList: { contains: () => false } },
  getElementById: (id: string) => { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); },
  createElement: () => ({ value: '', textContent: '', style: {}, setAttribute() {}, appendChild() {} }),
  addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
};
g.window = { devicePixelRatio: 1, addEventListener() {} };
g.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
g.requestAnimationFrame = () => 0;
g.cancelAnimationFrame = () => {};
g.Chart = class {
  data: any; options: any;
  constructor(_c: unknown, cfg: any) { this.data = cfg.data; this.options = cfg.options; }
  update() {} destroy() {}
};

const handlers = new Map<string, (d: any) => void>();
const sent: { ev: string; d: any }[] = [];
const socket: any = {
  on: (ev: string, fn: (d: any) => void) => { handlers.set(ev, fn); },
  emit: (ev: string, d: any) => { sent.push({ ev, d }); },
  off() {}, connected: true,
};

const m = require(OUT);
fs.rmSync(OUT, { force: true });
m.initInterfacesPage(socket, () => true);

const sel = els.get('ifaceSelect');
const names = (...n: string[]) => handlers.get('ifstatus:names')!({
  interfaces: n.map((name) => ({ name, running: true, disabled: false })) });
const history = (ifName: string) => m.onTrafficHistory({ ifName, points: [] });
const selects = () => sent.filter((s) => s.ev === 'traffic:select').map((s) => s.d.ifName);
// What main.ts's switchRouter does to these two modules.
const switchRouter = () => { m.resetTraffic(); m.resetInterfacesPage(); };

// ── on the first router, the AX3, whose WAN is WAN1 ──────────────────────────
names('WAN1', 'ether3', 'ether4');
history('WAN1');
assert.strictEqual(sel.value, 'WAN1');

// ── 1. switch, names first ───────────────────────────────────────────────────
{
  switchRouter();
  sent.length = 0;
  names('ether1', 'internal', 'lo');
  history('internal');
  assert.deepStrictEqual(selects(), [],
    'after a switch the picker asked for ' + JSON.stringify(selects()) +
    ', overriding the WAN the server subscribed this viewer to');
  assert.strictEqual(sel.value, 'internal', 'the picker shows ' + sel.value + ', not the WAN');
  say('ok  names first: graph and picker land on the new router\'s WAN, nothing asked for');
}

// ── 2. back, then switch again, history first ───────────────────────────────
{
  switchRouter();
  names('WAN1', 'ether3', 'ether4');
  history('WAN1');
  switchRouter();
  sent.length = 0;
  history('internal');
  names('ether1', 'internal', 'lo');
  assert.deepStrictEqual(selects(), [], 'the picker asked for ' + JSON.stringify(selects()));
  assert.strictEqual(sel.value, 'internal',
    'the picker shows ' + JSON.stringify(sel.value) + ' while the chart draws internal');
  say('ok  history first: the picker agrees with the chart');
}

// ── CONTROL: on one router, an interface that goes down still moves the graph ─
{
  sent.length = 0;
  names('ether1', 'lo');
  assert.deepStrictEqual(selects(), ['ether1'], 'the WAN went down and the graph did not move off it');
  assert.strictEqual(sel.value, 'ether1');
  say('ok  control: a vanished interface still moves the graph to the first live one');
}

say('router-switch-picker: all checks passed');
