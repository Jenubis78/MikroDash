/**
 * AN ADD FORM STARTS FROM ROUTEROS'S DEFAULT.
 *
 * A field's `Default` is what RouterOS holds when the property is not set. It
 * was applied when reading a row and never to an Add form, where a checkbox has
 * nothing to read and opens unticked - and an unticked box is SENT as `no`. A
 * new DHCP server went out with `conflict-detection=no` and a new adlist with
 * `ssl-verify=no`, both `yes` on the router. Found by opening the forms on a CHR.
 */
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const say = console.log.bind(console);
const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');

const ENTRY = path.join(ROOT, 'testdata', '.radd-entry.ts');
fs.writeFileSync(ENTRY, "export { initialValue, checkedValue } from '../web/src/resource.js';\n");
const OUT = path.join(ROOT, 'testdata', '.radd.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });

const { initialValue, checkedValue } = require(OUT);

const field = (over: Record<string, unknown>) => ({
  name: 'f', label: 'F', type: 'bool', input: 'checkbox', required: false, requiredOnCreate: false,
  options: null, placeholder: '', help: '', showIf: null, min: null, max: null, display: false,
  createOnly: false, tab: '', negatable: false, default: '', ...over,
});

const conflict = field({ name: 'conflictDetection', default: 'yes' });
assert.strictEqual(checkedValue(initialValue(conflict, null)), true,
  'a checkbox defaulting to yes opened unticked on Add, and would be sent as no');
say('ok  Add ticks a checkbox whose RouterOS default is yes');

assert.strictEqual(checkedValue(initialValue(field({ name: 'addArp', default: 'no' }), null)), false);
assert.strictEqual(checkedValue(initialValue(field({ name: 'plain' }), null)), false);
say('ok  a default of no, or none, stays unticked');

assert.strictEqual(initialValue(field({ name: 'keySize', input: 'select', default: '2048' }), null), '2048');
say('ok  a select or text field starts at its default too');

// CONTROL: Edit reads the row, whatever the default says.
assert.strictEqual(checkedValue(initialValue(conflict, { conflictDetection: false })), false,
  'an edit showed the default instead of the row');
assert.strictEqual(initialValue(conflict, {}), undefined);
say('ok  Edit shows the row, not the default');

assert.strictEqual(initialValue(field({ name: 'running', display: true, default: 'false' }), null), undefined,
  'a display field showed a state for a row that does not exist yet');
say('ok  a display field takes no default on Add');

fs.rmSync(OUT, { force: true });
say('resource-add-defaults: all checks passed');
