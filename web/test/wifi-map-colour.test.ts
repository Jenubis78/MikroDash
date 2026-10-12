/**
 * A FLOOR-PLAN COLOUR CANNOT CARRY CSS OF ITS OWN.
 *
 * objectColour() draws a stored object colour into an SVG element's style. A
 * stored "red;background:url(...)" would add declarations of its own - a request
 * to any URL from every browser that opens the plan. The server keeps only hex
 * colours on save (internal/sitedoc), and this pins the guard where the colour
 * is drawn, for plans saved before that.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'testdata', '.wifi-map-colour-entry.ts');
fs.writeFileSync(ENTRY, "export { objectColour } from '../web/src/pages/wifi-map.js';\n");
const OUT = path.join(ROOT, 'testdata', '.wifi-map-colour.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });
const { objectColour } = require(OUT) as { objectColour(c: string, alpha?: number): string };
fs.rmSync(OUT, { force: true });

for (const bad of ['red;background:url(https://x.test/)', '#38bdf8;background:url(https://x.test/)', 'url(x)', 'red', 'rgb(1,2,3)']) {
  assert.strictEqual(objectColour(bad), 'none', 'objectColour passed ' + JSON.stringify(bad) + ' into a style');
  assert.strictEqual(objectColour(bad, 0.133), 'none', 'objectColour passed ' + JSON.stringify(bad) + ' into a style');
}
assert.ok(objectColour('#38bdf8').includes('var(--accent-rx)'), 'a picker colour is drawn from the palette');
assert.strictEqual(objectColour('#123456'), '#123456', 'an unknown hex colour is drawn as stored');
console.log('  ok  a stored colour is a hex colour or nothing; it never adds CSS of its own');
