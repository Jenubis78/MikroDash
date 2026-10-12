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
    if (c.closest('.ff-toggle, .ff-multi, .ztp-choice, .stoggle-bare')) continue;
    // The recorded exceptions (internal/verify, controlExceptions): the
    // Terminal's prompt line and the template editor's code pane.
    if (c.id === 'terminalInput' || c.id === 'cfgEdBody') continue;
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
  // 4. A button on a compact control's line is compact too (.is-sm): a toolbar's
  // Load or Add beside its filters is the toolbar's height, not a form's.
  for (const c of modal.querySelectorAll('.sform-input.sform-sm')) {
    if (!shown(c)) continue;
    const cr = c.getBoundingClientRect(), cy = cr.top + cr.height / 2;
    for (const b of c.parentElement.querySelectorAll(':scope > .sbtn, :scope > * > .sbtn')) {
      if (!shown(b)) continue;
      const br = b.getBoundingClientRect();
      if (Math.abs(br.top + br.height / 2 - cy) < 6 && Math.abs(br.height - cr.height) > 0.5) {
        issues.push(`${name(b)}: a button on a toolbar control's line is ${br.height.toFixed(1)}px, the control ${cr.height.toFixed(1)}px - give it .is-sm`);
      }
    }
  }
  // 5. A button in a table row is row-sized, so the row is no taller for having it.
  const xs = document.createElement('div');
  xs.style.cssText = 'position:absolute;visibility:hidden;height:var(--ctl-h-xs)';
  document.body.appendChild(xs);
  const xsH = xs.getBoundingClientRect().height;
  xs.remove();
  for (const b of modal.querySelectorAll('td .sbtn')) {
    if (!shown(b)) continue;
    const h = b.getBoundingClientRect().height;
    if (Math.abs(h - xsH) > 0.5) issues.push(`${name(b)}: a button in a table row is ${h.toFixed(1)}px, --ctl-h-xs is ${xsH.toFixed(1)}px`);
  }
  // 6. One table density (app.css TABLES): every cell's padding is the tokens',
  // every header .66rem, and a row is --tbl-row-h tall unless a cell's content is
  // itself taller. The section's recorded exceptions are skipped by class.
  const tp = document.createElement('div');
  tp.style.cssText = 'position:absolute;visibility:hidden;box-sizing:content-box;padding:var(--tbl-pad-y) var(--tbl-pad-x);height:var(--tbl-row-h);font-size:.66rem';
  document.body.appendChild(tp);
  const tcs = getComputedStyle(tp);
  const padY = tcs.paddingTop, padX = tcs.paddingLeft, rowH = parseFloat(tcs.height), thFont = tcs.fontSize;
  tp.remove();
  const cellExempt = '.tbl-empty, .tbl-pick, .tbl-indent, .fw-dragcell, .fw-movecell';
  const rowExempt = '.res-drag-origin, .wl-group-row, .cfg-hist-open';
  for (const table of modal.querySelectorAll('table')) {
    if (!shown(table)) continue;
    const tname = table.id || String(table.className) || 'table';
    const seen = new Set();
    const once = (key, msg) => { if (!seen.has(key)) { seen.add(key); issues.push(`${tname}: ${msg}`); } };
    for (const c of table.querySelectorAll('th, td')) {
      if (!shown(c) || c.matches(cellExempt) || c.closest(rowExempt)) continue;
      const cs = getComputedStyle(c);
      if (cs.paddingTop !== padY || cs.paddingLeft !== padX) once('pad', `a ${c.tagName.toLowerCase()} is padded ${cs.paddingTop} ${cs.paddingLeft}, the table tokens are ${padY} ${padX}`);
      if (c.tagName === 'TH' && cs.fontSize !== thFont) once('th', `a header is ${cs.fontSize}, not .66rem (${thFont})`);
    }
    for (const tr of table.querySelectorAll('tbody > tr')) {
      if (!shown(tr) || tr.matches(rowExempt) || tr.querySelector(cellExempt)) continue;
      const h = tr.getBoundingClientRect().height;
      if (h < rowH - 1) { once('short', `a row is ${h.toFixed(1)}px, shorter than --tbl-row-h (${rowH.toFixed(1)}px)`); continue; }
      if (h <= rowH + 1) continue;
      // Taller is allowed only when a cell's own content needs it.
      const room = rowH - 2 * parseFloat(padY) + 1;
      const tall = [...tr.children].some((td) => {
        const r = document.createRange();
        r.selectNodeContents(td);
        return r.getBoundingClientRect().height > room;
      });
      if (!tall) once('tall', `a row is ${h.toFixed(1)}px with no cell content taller than the row - something pads it`);
    }
  }
  return { ok: issues.length === 0, fields: fields.length, issues };
})();
