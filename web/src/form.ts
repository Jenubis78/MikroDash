// The one way a dialog field is drawn: label, control, help.
//
// ── WHY A HELPER AND NOT A CONVENTION ───────────────────────────────────────
//
// Dialog fields were assembled by hand wherever they were needed, each with its
// own inline margins and help-text styling, so no stylesheet could line them up
// and nothing noticed when they did not. Every field built in TypeScript now
// comes from here, and the HTML templates copy the same markup; the stylesheet's
// "FORM FIELDS" section is the other half of the contract, and DESIGN.md states
// it. Nothing here writes a `style` attribute: spacing and colour belong to the
// stylesheet, where a palette and the light theme can reach them.

import { esc } from './dom';

export interface FieldOpts {
  /** The control's id, which the label points at. Omitted when the control is
   *  not a single labelable element (a checklist), so no `for` names a div. */
  id?: string;
  label: string;
  required?: boolean;
  /** One line under the control. Empty keeps the row's shape. */
  help?: string;
  /** Spans both columns: a list, a block of text. */
  full?: boolean;
  /** Extra attributes for the field's wrapper, already escaped: `data-res-field="x"`. */
  attrs?: string;
}

/**
 * A field: its label, the control it is given, and its help line.
 *
 * The help element is ALWAYS emitted, empty or not. Each field is a subgrid of
 * three rows, and a field missing its third would let the next field's label
 * slide up into that row.
 */
export function fieldHtml(o: FieldOpts, control: string): string {
  return '<div class="ff' + (o.full ? ' ff-full' : '') + '"' + (o.attrs ? ' ' + o.attrs : '') + '>' +
    '<label class="sform-label"' + (o.id ? ' for="' + esc(o.id) + '"' : '') + '>' + esc(o.label) +
    (o.required ? ' <span class="ff-req">*</span>' : '') + '</label>' +
    control +
    '<div class="ff-help">' + (o.help ? esc(o.help) : '') + '</div>' +
    '</div>';
}

/**
 * A toggle as a control: the same box as an input, the switch inside it, and
 * Off or On written by the stylesheet. Its label is the field's, above it.
 */
export function toggleHtml(id: string, checked: boolean, inputAttrs = ''): string {
  return '<label class="ff-toggle"><span class="ff-toggle-state"></span>' +
    '<span class="stoggle-switch"><input type="checkbox" id="' + esc(id) + '"' +
    (checked ? ' checked' : '') + (inputAttrs ? ' ' + inputAttrs : '') + '>' +
    '<span class="stoggle-track"></span><span class="stoggle-thumb"></span></span></label>';
}
