// A SELECT IS AS WIDE AS ITS WIDEST OPTION, AS A NATIVE ONE IS.
//
// Where the browser lets the page draw a select's open list (appearance:
// base-select, app.css), the closed box is sized by the option it shows, not
// the widest one: the time window on the Traffic card fell from 90px to 54px,
// and 21 selects on 15 pages narrowed the same way. A native select's floor is
// its widest option, so each select gets that floor back as a min-width,
// measured in its own font, and re-measured when a page refills it.
//
// An authored max-width still wins (the Traffic card's interface select stops
// at 130px), as it did for the native box.

/** The narrowest a select may be: its widest option plus its own padding and
 *  border (`chrome`), never past `maxWidth`. */
export function selectFloor(texts: string[], measure: (s: string) => number, chrome: number, maxWidth: number | null): number {
  let widest = 0;
  for (const t of texts) widest = Math.max(widest, measure(t));
  const floor = Math.ceil(widest + chrome);
  return maxWidth === null ? floor : Math.min(floor, maxWidth);
}

let ctx: CanvasRenderingContext2D | null = null;

function fit(sel: HTMLSelectElement): void {
  if (sel.multiple || sel.size > 1) return;
  ctx ??= document.createElement('canvas').getContext('2d');
  if (!ctx) return;
  const c = getComputedStyle(sel);
  const m = ctx;
  m.font = c.fontWeight + ' ' + c.fontSize + ' ' + c.fontFamily;
  const px = (v: string): number => parseFloat(v) || 0;
  const chrome = px(c.paddingLeft) + px(c.paddingRight) + px(c.borderLeftWidth) + px(c.borderRightWidth);
  const max = c.maxWidth.endsWith('px') ? px(c.maxWidth) : null;
  // A group's heading is a row of the list too, and a native box counted it.
  const texts = [...Array.from(sel.options, (o) => o.label || o.text),
    ...Array.from(sel.querySelectorAll('optgroup'), (g) => g.label)];
  sel.style.minWidth = selectFloor(texts, (s) => m.measureText(s).width, chrome, max) + 'px';
}

/** Fit every select now, and again whenever options change or fonts load. */
export function initSelectWidths(): void {
  if (typeof CSS === 'undefined' || !CSS.supports('appearance', 'base-select')) return;
  const pending = new Set<HTMLSelectElement>();
  let queued = false;
  const queue = (s: HTMLSelectElement): void => {
    pending.add(s);
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      for (const p of pending) fit(p);
      pending.clear();
    });
  };
  const all = (): void => document.querySelectorAll('select').forEach(queue);
  new MutationObserver((records) => {
    for (const r of records) {
      const n = r.target instanceof Element ? r.target : r.target.parentElement;
      const sel = n?.closest('select');
      if (sel) { queue(sel); continue; }
      r.addedNodes.forEach((a) => {
        if (a instanceof HTMLSelectElement) queue(a);
        else if (a instanceof Element) a.querySelectorAll('select').forEach(queue);
      });
    }
  }).observe(document.body, { childList: true, subtree: true, characterData: true });
  all();
  void document.fonts?.ready.then(all);
}
