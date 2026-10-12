// The palette, for colour set from code.
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//
// A colour written out in code - 'rgba(56,189,248,.15)' - is the default
// palette's, whatever palette or theme the viewer chose. The stylesheets take
// every colour from the palette (internal/verify holds them to it), and this is
// the same rule for the colour scripts set: a chart's lines, a gauge's arc, a
// map's fills, a status dot drawn in markup.
//
// Two shapes, because two kinds of consumer:
//
//   paletteCss(token, alpha)     a CSS colour string, for anything the browser
//                                styles: innerHTML style attributes, element.style,
//                                an SVG's style. It follows a palette change by itself.
//   paletteColour(token, alpha)  the resolved colour, for a <canvas> or Chart.js,
//                                which cannot read a CSS variable. Re-read it when
//                                onPaletteChange fires and redraw.

export type PaletteToken =
  | '--accent-rx' | '--accent-tx' | '--accent-ok' | '--accent-warn' | '--accent-err'
  | '--accent-alt' | '--accent-pink' | '--text-main' | '--text-muted' | '--border'
  | '--bg-deep' | '--bg-card';

/** A CSS colour for `token` at `alpha`: the palette's own, as the browser styles it. */
export function paletteCss(token: PaletteToken, alpha = 1): string {
  return 'rgb(from var(' + token + ') r g b / ' + alpha + ')';
}

const cache = new Map<string, string>();
let probe: HTMLElement | null = null;

/**
 * The concrete colour for `token` at `alpha`, as `rgba(r, g, b, a)`, for a canvas
 * or a chart. Resolved by the browser itself (a hidden element styled with
 * paletteCss), so it is exactly what the stylesheet would draw.
 */
export function paletteColour(token: PaletteToken, alpha = 1): string {
  const key = token + '|' + alpha;
  const hit = cache.get(key);
  if (hit) return hit;
  if (typeof document === 'undefined' || !document.body || typeof getComputedStyle === 'undefined') {
    return paletteCss(token, alpha);
  }
  if (!probe) {
    probe = document.createElement('span');
    probe.setAttribute('aria-hidden', 'true');
    probe.style.cssText = 'position:absolute;width:0;height:0;overflow:hidden;visibility:hidden';
    document.body.appendChild(probe);
  }
  probe.style.color = paletteCss(token, alpha);
  const out = toRgba(getComputedStyle(probe).color) || paletteCss(token, alpha);
  cache.set(key, out);
  return out;
}

/** `rgb(...)`, `rgba(...)` or `color(srgb r g b / a)` as `rgba(r, g, b, a)`. */
export function toRgba(c: string | undefined | null): string | null {
  if (typeof c !== 'string') return null;
  let m = c.match(/rgba?\(([^)]+)\)/);
  if (m) {
    const p = m[1]!.split(/[\s,/]+/).filter(Boolean).map(Number);
    return 'rgba(' + p[0] + ', ' + p[1] + ', ' + p[2] + ', ' + (p.length > 3 ? p[3] : 1) + ')';
  }
  m = c.match(/color\(srgb ([^)]+)\)/);
  if (m) {
    const p = m[1]!.split(/[\s/]+/).filter(Boolean).map(Number);
    const ch = (x: number): number => Math.round(x * 255);
    return 'rgba(' + ch(p[0]!) + ', ' + ch(p[1]!) + ', ' + ch(p[2]!) + ', ' + (p.length > 3 ? p[3] : 1) + ')';
  }
  return null;
}

const listeners = new Set<() => void>();
let observing = false;

/**
 * Call `cb` whenever the palette or the light/dark theme changes, so anything
 * drawn with paletteColour can redraw. Returns a function that unsubscribes.
 */
export function onPaletteChange(cb: () => void): () => void {
  listeners.add(cb);
  if (!observing && typeof MutationObserver !== 'undefined' && typeof document !== 'undefined') {
    observing = true;
    new MutationObserver(() => {
      cache.clear();
      listeners.forEach((f) => f());
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-palette', 'data-theme'] });
  }
  return () => { listeners.delete(cb); };
}
