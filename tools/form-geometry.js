// form-geometry.js - measures the open dialog against the form-field contract.
//
// Paste into the browser console, or run it with Playwright's evaluate, while a
// dialog is open (and on each of its tabs), or with none open to measure the
// page on screen. It returns { ok, fields, issues }.
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//
// The repository's tests prove the markup is right: every field an .ff, no
// inline style, a themed placeholder rule. None of them can see a pixel, and the
// dialog inconsistencies that prompted the form contract (a toggle 38px in one
// row and 54px in the next, rows staggered by help text, a select a few pixels
// off its neighbour, the browser's own placeholder grey) were all geometry. So
// geometry is measured here, in a real browser, as part of live verification:
// DESIGN.md says when to run it.
//
// It must be able to FAIL: run it once against a dialog you have broken on
// purpose (give one input `style="height:50px"`) before trusting a pass.
(() => {
  const issues = [];
  // The open dialog, or with none open, the page on screen: a page's own forms
  // (Settings, a tool's run controls) follow the same contract.
  const modal = [...document.querySelectorAll('.rtr-modal-bg.open .rtr-modal')].find((m) => m.getClientRects().length) ||
    [...document.querySelectorAll('[id^="page-"].active')].find((m) => m.getClientRects().length);
  if (!modal) return { ok: false, fields: 0, issues: ['no dialog is open and no page is active'] };
  // In a dialog every control is a field. A page may also have a lone toolbar
  // control (a search box, a filter) that is an .sform-input with no label.
  const isDialog = modal.classList.contains('rtr-modal');

  const probe = document.createElement('div');
  probe.style.cssText = 'position:absolute;visibility:hidden;height:var(--ctl-h);color:var(--text-muted)';
  document.body.appendChild(probe);
  const ctlH = probe.getBoundingClientRect().height;
  const muted = getComputedStyle(probe).color;
  probe.remove();
  if (!ctlH) issues.push('--ctl-h is not defined');

  const shown = (e) => e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden';
  const name = (e) => e.id || e.getAttribute('data-res-field') || String(e.className) || e.tagName;

  // 1. Every control on screen sits in a field.
  for (const c of modal.querySelectorAll('input, select, textarea')) {
    if (c.type === 'hidden' || c.type === 'file') continue;
    // A toggle, a checklist, or a choice card (a whole card is the option, its
    // radio hidden inside it) - each draws its own box.
    if (c.closest('.ff-toggle, .ff-multi, .ztp-choice')) continue;
    if (!shown(c)) continue;
    // A table's selection column: a checkbox per row is the table's, not a field.
    if ((c.type === 'checkbox' || c.type === 'radio') && c.closest('td, th')) continue;
    if (c.type === 'checkbox' || c.type === 'radio') {
      issues.push(`bare ${c.type} ${name(c)}: a toggle is .ff-toggle, a set of options .ff-multi`);
      continue;
    }
    // A cell of a data-entry table is labelled by its column header, so it needs
    // no field around it - but it is still the one control.
    if (isDialog && !c.closest('.ff') && !c.closest('td')) issues.push(`${name(c)} is not inside an .ff field`);
    if (!c.classList.contains('sform-input')) issues.push(`${name(c)} is not an .sform-input`);
  }

  // 2. Fields: the right shape, nothing inline, the shared height, the themed placeholder.
  const fields = [...modal.querySelectorAll('.ff')].filter(shown);
  for (const f of fields) {
    for (const part of [f, ...f.querySelectorAll('.sform-label, .sform-input, .ff-help, .ff-toggle')]) {
      const st = part.getAttribute('style');
      // `display:` is how a field is shown and hidden; nothing else may be inline.
      if (st && !/^\s*(display:\s*[a-z]*;?\s*)?$/.test(st)) issues.push(`${name(part)} carries style="${st}"`);
    }
    // A location search's suggestion list is absolutely positioned: no row.
    const kids = [...f.children].filter((k) => !k.classList.contains('cpick-list'));
    if (kids.length !== 3 || !kids[0].classList.contains('sform-label') || !kids[2].classList.contains('ff-help')) {
      issues.push(`${name(f)} is not label, control, help`);
      continue;
    }
    const ctl = kids[1];
    // A label starts where its control starts, never centred or pushed right.
    const lx = kids[0].getBoundingClientRect().left, cx = ctl.getBoundingClientRect().left;
    if (Math.abs(lx - cx) > 1) issues.push(`${name(f)}: label starts at ${lx.toFixed(1)}px, its control at ${cx.toFixed(1)}px`);
    const box = ctl.matches('.sform-input, .ff-toggle') ? ctl : ctl.querySelector('.sform-input');
    const tall = ctl.matches('textarea, .ff-multi, select[multiple], select[size]');
    if (box && !tall) {
      const h = box.getBoundingClientRect().height;
      if (Math.abs(h - ctlH) > 0.5) issues.push(`${name(f)}: control is ${h.toFixed(1)}px, --ctl-h is ${ctlH.toFixed(1)}px`);
    }
    // A row of controls (Stream/Poll, a search and its button): every box in it
    // is a control, buttons included.
    if (ctl.matches('.ff-row, .cpick-row, .res-neg-row')) {
      for (const k of ctl.children) {
        if (!k.matches('button, .sform-input, .ff-toggle, .bw-unit-toggle') || !shown(k)) continue;
        const h = k.getBoundingClientRect().height;
        if (Math.abs(h - ctlH) > 0.5) issues.push(`${name(f)}: ${name(k)} in its control row is ${h.toFixed(1)}px, --ctl-h is ${ctlH.toFixed(1)}px`);
      }
    }
    for (const inp of f.querySelectorAll('input.sform-input, textarea.sform-input')) {
      const ph = getComputedStyle(inp, '::placeholder').color;
      if (inp.placeholder && ph !== muted) issues.push(`${name(f)}: placeholder is ${ph}, not --text-muted (${muted})`);
    }
  }

  // 3. Fields side by side share their label line and their control line.
  // A row is the fields of one grid whose boxes start on the same line.
  const grids = [];
  const rows = new Map();
  for (const f of fields) {
    const grid = f.parentElement;
    if (!grid.classList.contains('ff-grid')) continue;
    if (grids.indexOf(grid) === -1) grids.push(grid);
    const id = grids.indexOf(grid) + ':' + Math.round(f.getBoundingClientRect().top);
    if (!rows.has(id)) rows.set(id, []);
    rows.get(id).push(f);
  }
  for (const row of rows.values()) {
    if (row.length < 2) continue;
    for (const part of [0, 1]) {
      const tops = row.map((f) => f.children[part].getBoundingClientRect().top);
      if (Math.max(...tops) - Math.min(...tops) > 0.5) {
        issues.push(`row ${row.map(name).join(' | ')}: ${part ? 'controls' : 'labels'} start at ${tops.map((t) => t.toFixed(1)).join(' / ')}`);
      }
    }
  }
  return { ok: issues.length === 0, fields: fields.length, issues };
})();
