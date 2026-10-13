/**
 * A SELECT IS AS WIDE AS ITS WIDEST OPTION (2026-10-13).
 *
 * Where the page draws a select's open list (appearance: base-select), the
 * closed box is sized by the option it shows, so web/src/select-width.ts gives
 * each select its widest option back as a min-width. This drives the floor:
 *
 *   - the widest option decides, not the first or the selected one;
 *   - the select's own padding and border are added, and the sum rounds up;
 *   - an authored max-width still caps it;
 *   - the CONTROL: an empty select's floor is its padding and border alone.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const say = console.log.bind(console);
const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'testdata', '.select-width-entry.ts');
fs.writeFileSync(ENTRY, "export { selectFloor } from '../web/src/select-width.js';\n");
const OUT = path.join(ROOT, 'testdata', '.select-width.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });
const { selectFloor } = require(OUT);
fs.rmSync(OUT, { force: true });

// Seven pixels a character: the mono font's advance, near enough.
const measure = (s) => s.length * 7;

assert.strictEqual(selectFloor(['1m', '5m', '15m', '30m'], measure, 45.2, null), 67,
  'the widest option (3 chars, 21px) plus 45.2px of padding and border, rounded up');
assert.strictEqual(selectFloor(['All Clients', 'a', 'host-name-8d34.example'], measure, 40, null), 194,
  'the widest option decides, wherever it sits in the list');
assert.strictEqual(selectFloor(['a-very-long-interface-name'], measure, 40, 130), 130,
  'an authored max-width still caps the floor');
assert.strictEqual(selectFloor([], measure, 40, null), 40,
  'CONTROL: no options leaves padding and border alone');
say('select-width: 4 checks passed');
