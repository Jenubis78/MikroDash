---
version: alpha
name: MikroDash
description: A dark-first, dense operations console for MikroTik RouterOS fleets. Live numbers in monospace on translucent cards over a near-black field.
colors:
  primary: "#38bdf8"
  secondary: "#34d399"
  tertiary: "#a78bfa"
  neutral: "#07090f"
  surface: "rgba(13,18,30,.85)"
  on-surface: "rgba(200,215,240,.9)"
  on-surface-muted: "rgba(148,163,190,.55)"
  border: "rgba(99,130,190,.13)"
  nav: "rgba(5,8,16,.92)"
  rx: "#38bdf8"
  tx: "#34d399"
  ok: "#4ade80"
  warn: "#f59f00"
  error: "#f87171"
  alt: "#a78bfa"
  pink: "#f472b6"
  light-neutral: "#e8eaee"
  light-surface: "rgba(255,255,255,.92)"
  light-on-surface: "#1a2030"
  light-on-surface-muted: "#5f7196"
  light-border: "#b1bbcf"
  light-rx: "#247ba1"
  light-tx: "#20835f"
typography:
  wordmark:
    fontFamily: Orbitron
    fontSize: 1.2rem
    fontWeight: 700
    letterSpacing: -0.02em
  stat-lg:
    fontFamily: JetBrains Mono
    fontSize: 1.9rem
    fontWeight: 700
    lineHeight: 1
  stat-md:
    fontFamily: JetBrains Mono
    fontSize: 1.3rem
    fontWeight: 600
  page-title:
    fontFamily: Oxanium
    fontSize: 0.85rem
    fontWeight: 600
    letterSpacing: 0.01em
  card-title:
    fontFamily: Oxanium
    fontSize: 0.82rem
    fontWeight: 600
    letterSpacing: 0.04em
  body-md:
    fontFamily: Oxanium
    fontSize: 0.8rem
    fontWeight: 400
    lineHeight: 1.5
  label-caps:
    fontFamily: Oxanium
    fontSize: 0.72rem
    fontWeight: 600
    letterSpacing: 0.06em
  table-head:
    fontFamily: Oxanium
    fontSize: 0.66rem
    fontWeight: 400
    letterSpacing: 0.06em
  data-md:
    fontFamily: JetBrains Mono
    fontSize: 0.72rem
    fontWeight: 400
  data-sm:
    fontFamily: JetBrains Mono
    fontSize: 0.68rem
    fontWeight: 600
  pill:
    fontFamily: JetBrains Mono
    fontSize: 0.62rem
    fontWeight: 400
rounded:
  xs: 3px
  sm: 4px
  badge: 5px
  md: 6px
  lg: 10px
  xl: 12px
  full: 999px
spacing:
  xs: 0.25rem
  sm: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  card-header-y: 0.65rem
  card-header-x: 1rem
  modal-x: 1.1rem
  nav-collapsed: 52px
  nav-open: 190px
components:
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.lg}"
  card-title:
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.card-title}"
  count-badge:
    backgroundColor: "rgba(99,130,190,.12)"
    textColor: "rgba(148,163,190,.7)"
    typography: "{typography.data-sm}"
    rounded: "{rounded.badge}"
  count-badge-active-blue:
    backgroundColor: "rgba(56,189,248,.15)"
    textColor: "rgba(56,189,248,.9)"
  tab:
    textColor: "{colors.on-surface-muted}"
    padding: 0.5rem
  tab-active:
    textColor: "{colors.rx}"
  button-primary:
    backgroundColor: "rgba(56,189,248,.15)"
    textColor: "{colors.rx}"
    rounded: "{rounded.md}"
    padding: 0.5rem
  button-primary-hover:
    backgroundColor: "rgba(56,189,248,.25)"
  button-danger:
    backgroundColor: "rgba(248,113,113,.12)"
    textColor: "rgba(248,113,113,.9)"
    rounded: "{rounded.md}"
  input:
    backgroundColor: "{colors.neutral}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.md}"
    padding: 0.45rem
  pill-ok:
    backgroundColor: "rgba(74,222,128,.1)"
    textColor: "{colors.ok}"
    typography: "{typography.pill}"
    rounded: "{rounded.sm}"
  pill-warn:
    backgroundColor: "rgba(245,159,0,.1)"
    textColor: "{colors.warn}"
    rounded: "{rounded.sm}"
  pill-bad:
    backgroundColor: "rgba(248,113,113,.1)"
    textColor: "{colors.error}"
    rounded: "{rounded.sm}"
  pill-info:
    backgroundColor: "rgba(56,189,248,.1)"
    textColor: "{colors.rx}"
    rounded: "{rounded.sm}"
  pill-neutral:
    backgroundColor: "rgba(99,130,190,.07)"
    textColor: "{colors.on-surface-muted}"
    rounded: "{rounded.sm}"
  modal:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.xl}"
    width: 960px
---

# DESIGN.md

How MikroDash looks, and the rules a new screen follows so it looks like the rest of the app. Read
this before any UI work. `CLAUDE.md` ("A new page's furniture") holds the page-layout rules that tests
enforce; this file covers the visual language around them.

**The stylesheet is the source of truth.** The tokens above are the default dark palette, copied
from `:root` in `web/public/app.css`. Components never use them as literals: they use the CSS custom
properties (`var(--accent-rx)` and so on) so that every palette, the light theme and the Appearance
settings can restyle them.

## Overview

MikroDash is a network operations console for people who run MikroTik routers. It is used for long
stretches, often on a second screen, so it is **dark first, dense and calm**:

- **Data first.** Most of the screen is numbers, names and states from routers. Decoration only
  helps you read those faster.
- **Live.** Values update in place over a WebSocket. Movement means the network changed, never
  that the UI wants attention.
- **Technical, not playful.** The square, slightly futuristic Oxanium for the interface, JetBrains
  Mono for every value a router reports, and the Orbitron wordmark.
- **Glass on night.** Translucent cards over a near-black background with two faint glows (blue at
  the top left, green at the bottom right). Thin blue-grey borders separate things; heavy shadows
  are not used.

## Colors

All colours are CSS custom properties on `:root`, and the palette layer swaps them:

- **17 palettes**: the default plus Nord, Catppuccin, Dracula, Tokyo, Gruvbox, Rosé Pine (and Moon),
  One Dark, Solarized, Everforest, Kanagawa, Monokai (and Pro), Material, Palenight and GitHub.
- **A light theme** for the default and for eight of the named palettes
  (`html[data-theme="light"]`).
- **Per-browser Appearance settings** (`web/src/appearance.ts`) for contrast, text and background
  brightness, font and font size.

A hard-coded colour drops out of all of that, so components never use one.

### Surfaces and text

| Role | Property | Default (dark) |
|---|---|---|
| Page background | `--bg-deep` | Night `#07090f` |
| Card, modal | `--bg-card` | Translucent ink `rgba(13,18,30,.85)` |
| Divider, outline | `--border` | Faint steel `rgba(99,130,190,.13)` |
| Primary text | `--text-main` | Pale steel `rgba(200,215,240,.9)` |
| Labels, metadata | `--text-muted` | Dim steel `rgba(148,163,190,.55)` |
| Side nav, top bar | `--nav-bg`, `--topbar-bg` | Near-black glass |

### Meaning

Every accent has a job, and the jobs do not move:

- **`--accent-rx`, sky blue: received traffic, and the interactive accent.** It colours Rx values,
  the active tab, focused inputs, primary buttons, links and info pills.
- **`--accent-tx`, emerald: transmitted traffic.** It colours Tx values and UDP.
- **Rx and Tx are fixed everywhere:** a received value is always `--accent-rx` and a transmitted one
  is always `--accent-tx`, on every page, chart and table.
- **`--accent-ok`, green:** up, running, bound, healthy.
- **`--accent-warn`, amber:** degraded, waiting, pending, and ICMP.
- **`--accent-err`, soft red:** down, failed, expired, and destructive actions.
- **`--accent-alt`, violet:** a secondary category, for example a service name.
- **`--accent-pink`:** a last series colour for charts that need one.

### How colour is applied

A state is a **tinted pill**, not a block of solid colour:

- the text in the accent colour;
- the background at about 10-15% of it;
- a 1px border at about 25-30% of it.

New code builds these with `color-mix(in srgb, var(--accent-ok) 13%, transparent)` so the tint
follows the palette. Older rules spell the default palette's `rgba()` out literally; don't copy
them.

## Typography

- **`--font-ui` (Oxanium)** for interface text: titles, labels, buttons, tabs, prose.
- **`--font-mono` (JetBrains Mono)** for anything a router reports: addresses, MACs, rates, counters,
  versions, interface names, timestamps, count pills and state pills.
- **Orbitron** for the wordmark only. Branding can swap it for another of the shipped fonts.
- **Always use the properties, never a family name.** The Appearance tab lets each user choose the UI
  font, from system fonts to about thirty bundled ones (`web/public/css/app-fonts.css`), and
  `var(--font-ui)` is how a component follows that choice.

The scale is small, because the app is dense:

| Use | Style |
|---|---|
| Hero numbers (Bandwidth, Connections) | mono, 1.3-1.9rem, 600-700 |
| Card titles | UI, .82rem, 600, UPPERCASE, .04em tracking, muted |
| Form labels, stat labels | UI, .65-.72rem, 600-700, UPPERCASE, .06-.08em tracking, muted |
| Table headers | UI, .66rem, UPPERCASE, .06em tracking, muted, with a sort caret |
| Table cells, values | mono, .68-.76rem |
| Pills | mono, .62-.68rem |

**Weights are 400, 600 and 700.** Uppercase with letter spacing marks a label; values are never
uppercased.

## Layout

The shell is the same on every page:

- **A left side nav**: 52px wide, opening to 190px on hover. Under 768px it becomes a drawer behind a
  burger button.
- **A top bar**: the wordmark, the page title and the router picker.
- **The page**: a stack or grid of cards.

Spacing is in rem, mostly from this ladder: .25, .4, .5, .65, .75, 1 and 1.5rem.

- Card header: .65rem by 1rem.
- Modal body: 1rem by 1.1rem.
- Gaps between pills and icons: .3-.4rem.

**Every page has the same furniture.** CLAUDE.md is the rule; tests enforce it:

- the title at the far left, with a blue count pill beside it;
- its tabs to the right of the title;
- actions alone in the right-hand `.hdr-actions` corner;
- sortable headers;
- its own nav icon;
- key columns as coloured pills.

Generated pages get all of this from `cmd/areagen` and `web/src/pages/area.ts`. A hand-built page
copies the same markup.

**Responsive:**

- Grids step down at roughly 1300, 1100, 980, 900, 760 and 620px, and end in one column.
- Toolbars and headers wrap rather than scroll.
- A wide table scrolls inside its card, never the page.
- Check every new screen at phone width and at a wide desktop.

## Elevation & Depth

Depth comes from **translucency and borders**, not from stacked shadows. There are three levels:

1. **The page**: `--bg-deep` with the two radial glows.
2. **Cards**: `--bg-card`, a 1px `--border` and one soft shadow, `0 4px 24px rgba(0,0,0,.25)`.
3. **Overlays**:
   - Modals sit on a `rgba(0,0,0,.55)` backdrop blurred 4px, with `0 16px 40px rgba(0,0,0,.5)`.
   - Banners and the mobile nav blur what is behind them.

**Inside a card, use borders and tint for structure, not a nested card.** A section inside a card
uses a border, a faint fill (`rgba(99,130,190,.04)`) or a tab bar.

**Card state is drawn on the card itself:**

- A device card has a 3px status stripe on its left edge.
- A card whose data has gone stale dims under its `.stale-overlay`. That overlay is always in the
  DOM; it is shown by opacity.

## Shapes

Corners are gently rounded, and the radius grows with the size of the element:

| Element | Radius |
|---|---|
| Keyboard keys, protocol tags | 3px |
| State pills, chips | 4px |
| Count pills, small chips | 5px |
| Buttons, inputs, selects, tab tops | 6px |
| Cards, the stale overlay | 10px |
| Modals | 12px |
| Status dots | 50% |
| Rare fully rounded tags | 999px |

**Icons are inline SVG line icons:**

- a 24px viewBox;
- a 2px stroke in `currentColor`, round caps and joins, no fill;
- drawn at 13-17px.

Each nav entry has its own icon that suits the page. **Don't use emoji as icons.** The one exception
is country flags.

## Components

Before writing new styles, reuse the existing class. The class names say where each one started, not
where it is limited to.

- **Card**: `.card` > `.card-header` (with `.card-title`) and `.card-body`.
- **Count pill**: `.card-badge`, plus `active-blue` or `active-green` when it is counting something
  live.
- **Tabs**: `.stab-bar` / `.stab`.
  - The active tab gets a 2px `--accent-rx` underline and blue text.
  - Page tabs use `rttab-bar` for the compact size.
- **Buttons**: `.sbtn` plus a variant, for every action.
  - `sbtn-primary` is the blue tint; the variants are `-outline`/`-ghost` (neutral), `-danger`,
    `-warn` and `-purple`. Pick by meaning: primary for the main action, danger for a destructive
    one, warn for a caution (a reboot).
  - **Two sizes, set by the control tokens.** The default is `--ctl-h`, for a form or a dialog's
    footer. `.is-sm` is `--ctl-h-sm`, for a toolbar, a card header or a table row: a button is as
    tall as the controls beside it. (`.is-sm`, not `sbtn-sm`: a bare button's hover is guarded with
    `:not([class*="sbtn-"])`.)
  - **A glyph-only button is `.icon-btn`**: a `--ctl-h-sm` square for the theme toggle, sign out,
    notifications, a map's zoom and refresh.
  - A button never carries its own height, padding, font size, fill or border, inline or in a page
    class; a page class may only place it. Tabs, chips, segmented choices, close and move glyphs and
    sort headers are components of their own, listed by name in `internal/verify`.
  - Buttons are tinted, not solid. Disabled is .4-.45 opacity with a `not-allowed` cursor.
- **Forms**: see "Form fields" below. Every field is a label, a control and a help line.
- **Modal**: `.rtr-modal-bg` > `.rtr-modal` with `-hdr`, `-body` and `-footer`.
  - The footer's actions are right-aligned.
  - Wide modals split the body into two columns from 900px.
  - The `pmodal` variant is a single 640px column for short forms.
- **State pills**: `.vpn-hs-badge` with
  - `hs-ok` (green),
  - `hs-warn` (amber),
  - `hs-stale` (red),
  - `hs-info` (blue),
  - `hs-never` (neutral).

  Generated pages pick these by **kind** (`state`, `action`, `good`, `warn`, `bad`, `info`), never by
  colour.
- **Protocols**: `protoPill()` in `web/src/dom.ts`.
  - TCP is blue, UDP is green, ICMP is amber and anything else is grey.
  - Firewall actions use `actionBadge`.
- **Tables**: use `renderSortHeader` / `sortRows`.
  - An **ordered** table (firewall chains, routing rules, IPsec policies, queues) keeps the router's
    order and its move arrows, and does not sort.
- **Live graphs**: a new graph uses the Dashboard traffic graph's mechanics:
  - it scrolls on server time;
  - its y-axis eases;
  - it stops animating while its page is hidden.
- **Empty and unknown**: a value the router did not send is a `-` in muted text. A `title` tooltip
  says why when the reason is useful, as the Public IP row does.

## Form fields

Every field in a dialog has the same shape, and the stylesheet owns all of it. The rules exist
because the dialogs drifted apart: toggles of two heights in one form, help text that staggered the
rows below it, a select a few pixels off its neighbours, and placeholders in the browser's own grey.

**The shape.** A field is three parts, always all three:

```html
<div class="ff-grid">
  <div class="ff">
    <label class="sform-label" for="host">Host <span class="ff-req">*</span></label>
    <input class="sform-input" id="host" placeholder="192.168.88.1">
    <div class="ff-help">The address to probe.</div>
  </div>
</div>
```

- **`.ff-grid`** lays fields out two to a row, one under 600px. Add `ff-one` for a single column,
  and `ff-full` on a field that needs both columns (a list, a block of text).
- **Each `.ff` is a subgrid of three rows.** Labels, boxes and help lines line up across a row
  whichever field has help, so the help element is **always** there, even empty.
- **In TypeScript, use `fieldHtml()` and `toggleHtml()`** from `web/src/form.ts`. In a template,
  copy the markup above exactly.

**The controls.**

- **One box for everything**: a text input, a number, a select and a locked display value are all
  `.sform-input`, `--ctl-h` tall, `--bg-deep`, with a 1px border that turns `--accent-rx` on focus.
- **Values are mono** (they are router data); labels are the UI font, uppercase and muted.
- **Placeholders are `--text-muted`.** A placeholder shows the default; it is never the browser's grey.
- **A select is drawn by the stylesheet**, chevron included, so it matches the inputs beside it.
- **A toggle is a field like any other**: an uppercase label above, and an `.ff-toggle` box of the
  same height as an input, reading Off or On beside the switch. The Settings page's `.stoggle`
  panel, with its label inside the box, is for page forms only, never a dialog.
- **A set of options chosen together** is one `.ff-multi` box, full width.
- **A data-entry table** (one input per router and variable) keeps its table: the column header is
  each input's label, and every cell's control is still `.sform-input`.

**Pages follow the same rules as dialogs.** A page's form (Settings, a card's options) is an
`.ff-grid` of fields exactly like a dialog's. Two page shapes are added:

- **A toolbar control** (a search box, a filter select in a card header) is unlabelled and compact:
  `class="sform-input sform-sm"`, `--ctl-h-sm` tall. It may be placed with `width`, `max-width` or
  `flex`, never resized. A filter that is narrowing the list adds `.active`, which draws it in the
  interactive accent so a filtered view never looks unfiltered.
- **There is one control.** Every text, number, select and textarea in the app is `.sform-input`;
  no page gives a control its own class for height, padding or colour. The two exceptions, held
  in `internal/verify`, are the Terminal's command line (a prompt on the terminal's surface) and
  Config Management's template editor (a full-height code pane). The sign-in page is standalone
  and keeps its own small stylesheet.
- **A one-row form** (a tool's run controls: target, count, Start) is `.ff-inline`: fields side by
  side, wrapping, with the action `.sbtn` level with the boxes. It shows no help lines; a field that
  needs explaining gets a note under the row.
- **The one other switch** is `.stoggle.stoggle-bare`: a bare switch set inside a sentence or an
  action bar ("Upgrade automatically" beside the firmware button), where it is an action, not a
  field. `internal/verify` holds the list of files allowed to draw one.
- **The vendored Tabler stylesheet's form classes** (`form-control`, `form-select`, `form-label`)
  are never used: they are a second control system with their own sizes and colours. Tabler is
  still loaded for its layout utilities.

**Never.**

- **No inline `style`** on a field or any part of one. The one exception is `display`, which a
  script sets to show or hide the whole `.ff` (never just its input, which would leave an empty
  label behind).
- **No per-dialog patch** to line something up. If a field does not fit the shape, fix the shape
  here and in the FORM FIELDS section of `app.css`, so every dialog gets the fix.

**How it is held.**

- `internal/verify/formfields_test.go` checks the templates and the TypeScript: every control in a
  dialog is in an `.ff`, toggles are `.ff-toggle`, nothing inline, and `app.css` still defines the
  control height, the subgrid and the themed placeholder.
- **Geometry needs a browser.** After changing a dialog, open it, visit each tab, and run
  `tools/form-geometry.js` in the console (or through Playwright's evaluate). It checks every
  control is `--ctl-h` tall, labels and boxes line up across each row, and placeholders take the
  palette's muted text. Break one field on purpose once, so you have seen it fail before you
  trust a pass.

## Do's and Don'ts

- **Do** use `var(--…)` for every colour and font. **Don't** write a hex or rgba literal for a new
  component, and don't add a colour to the palette to make something stand out.
- **Do** keep Rx blue and Tx green, everywhere.
- **Do** show a state as a tinted pill using its meaning colour. **Don't** use solid colour blocks or
  gradients on components.
- **Do** put router data in the mono font, and interface text in the UI font.
- **Do** check a new screen:
  - in the default palette;
  - in the light theme;
  - in one other palette;
  - at phone width.
- **Do** respect `prefers-reduced-motion`, and pause animations on pages that are not shown.
- **Do** reuse a component before writing a new one. If two pages need the same thing, they share the
  class.
- **Don't** use em dashes anywhere in the UI or the docs; use a hyphen.
- **Don't** add emoji icons, a new font, or a shadow to make something "pop".
- **Don't** give a page tabs, pills or a count pill it has no rows for. The Terminal and the Tools
  pages are the recorded exceptions in CLAUDE.md.
