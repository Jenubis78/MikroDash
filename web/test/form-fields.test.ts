/**
 * THE FIELD HELPER EMITS THE CONTRACT, AND NOTHING INLINE.
 *
 * Every dialog field built in TypeScript comes from fieldHtml() and
 * toggleHtml() in web/src/form.ts, so a mistake here is a mistake in every
 * dialog at once. Three things are pinned:
 *
 *   - the help element is ALWAYS emitted, even empty: each field is a subgrid
 *     of three rows, and a field without its third lets the next one's label
 *     ride up into the gap, which is the row stagger this contract exists to end;
 *   - no `style` attribute, anywhere: spacing belongs to the stylesheet;
 *   - what the caller passes is escaped, since labels and help can carry a
 *     router's own text.
 *
 * WHAT WOULD MAKE THIS PASS DISHONESTLY: a helper that only emits help when
 * there is help. So the empty case is asserted on its own.
 */

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const ROOT = process.env.MIKRODASH_ROOT || path.join(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'testdata', '.form-fields-entry.ts');
fs.writeFileSync(ENTRY, "export { fieldHtml, toggleHtml } from '../web/src/form.js';\n");
const OUT = path.join(ROOT, 'testdata', '.form-fields.cjs');
execFileSync(path.join(ROOT, 'web', 'node_modules', '.bin', 'esbuild'),
  [ENTRY, '--bundle', '--format=cjs', '--platform=node', '--outfile=' + OUT, '--log-level=warning'],
  { stdio: 'inherit' });
fs.rmSync(ENTRY, { force: true });
const mod = require(OUT);
fs.rmSync(OUT, { force: true });

const { fieldHtml, toggleHtml } = mod as {
  fieldHtml(o: { id: string; label: string; required?: boolean; help?: string; full?: boolean; attrs?: string },
    control: string): string;
  toggleHtml(id: string, checked: boolean, inputAttrs?: string): string;
};

const say = (s: string): void => console.log('  ok  ' + s);

// ── the empty help row is there ─────────────────────────────────────────────
{
  const html = fieldHtml({ id: 'x', label: 'Name' }, '<input class="sform-input" id="x">');
  assert.strictEqual(html,
    '<div class="ff"><label class="sform-label" for="x">Name</label>' +
    '<input class="sform-input" id="x"><div class="ff-help"></div></div>',
    'a field without help must still emit its empty .ff-help, or the next row rides up');
  say('a field with no help still has its help row');
}

// ── required, full width, wrapper attributes, help ──────────────────────────
{
  const html = fieldHtml({ id: 'h', label: 'Host', required: true, full: true, help: 'The address',
    attrs: 'data-res-field="host"' }, '<input class="sform-input" id="h">');
  assert.ok(html.startsWith('<div class="ff ff-full" data-res-field="host">'), html);
  assert.ok(html.includes('Host <span class="ff-req">*</span></label>'), html);
  assert.ok(html.endsWith('<div class="ff-help">The address</div></div>'), html);
  say('required star, full width, wrapper attributes and help land where the stylesheet expects');
}

// ── escaped, and never styled ───────────────────────────────────────────────
{
  const html = fieldHtml({ id: 'a"b', label: '<b>x</b>', help: 'a & b' }, '') + toggleHtml('t"1', true);
  assert.ok(!/style=/.test(html), 'the helper wrote an inline style: ' + html);
  assert.ok(html.includes('for="a&quot;b"') && html.includes('&lt;b&gt;x&lt;/b&gt;') && html.includes('a &amp; b'), html);
  assert.ok(html.includes('id="t&quot;1"'), html);
  say('labels, help and ids are escaped, and no style attribute is written');
}

// ── a toggle is a control-height box with its state ─────────────────────────
{
  const on = toggleHtml('dis', true, 'data-x="1"');
  assert.ok(on.startsWith('<label class="ff-toggle"><span class="ff-toggle-state"></span>'), on);
  assert.ok(on.includes('<input type="checkbox" id="dis" checked data-x="1">'), on);
  assert.ok(!toggleHtml('dis', false).includes(' checked'), 'an off toggle rendered checked');
  say('a toggle is the .ff-toggle box, checked only when asked');
}
