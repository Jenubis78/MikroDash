package verify

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// EVERY DIALOG FIELD IS ONE SHAPE: LABEL, CONTROL, HELP.
//
// ── THE DEFECT THIS EXISTS FOR ──────────────────────────────────────────────
//
// Measured on the NetWatch dialog, 2026-10-12: a toggle 38px tall in one row and
// 54px in the next, help text staggering every row below it, a select a few
// pixels off the inputs beside it, and placeholders in the browser's own grey.
// The text box, the select and the toggle had been built for the Settings page,
// one per line, and every dialog assembled them by hand with its own inline
// margins. Each mismatch was patched where somebody saw it, and nothing stopped
// the next dialog repeating all of them, because no check reads a stylesheet or
// a field's markup.
//
// ── WHAT IS CHECKED HERE, AND WHAT IS NOT ───────────────────────────────────
//
// The MARKUP and the STYLESHEET's half of the contract: every control in a
// dialog sits in an `.ff` of exactly label, control and help; toggles are
// `.ff-toggle`, never the Settings page's `.stoggle` panel; no part of a field
// carries an inline style; and app.css still defines the one control height,
// the subgrid and the themed placeholder. GEOMETRY - whether the boxes really
// line up - needs a browser, and tools/form-geometry.js measures it there. A
// green run here says the markup is right, not that the pixels are.
//
// ── IT FAILS IN BOTH DIRECTIONS ─────────────────────────────────────────────
//
// An exception recorded below that no longer breaks a rule fails, so the list
// cannot outlive its reasons.

// dialogControlExceptions are controls in a dialog that are not fields, each
// with why. Keyed "file#id".
var dialogControlExceptions = map[string]string{}

// stoggleFiles are the TypeScript files that may still draw the Settings page's
// `.stoggle` panel, because what they draw is on a PAGE, not in a dialog. A
// dialog toggle is `.ff-toggle`, from toggleHtml() in web/src/form.ts.
var stoggleFiles = map[string]string{
	"web/src/pages/settings.ts": "the Settings page's per-area visibility toggles, a page form",
	"web/src/pages/packages.ts": "the bare switch beside the firmware upgrade button on the Packages page: an action, not a field",
	"web/src/pages/interfaces-history.ts": "the bare switch inside the traffic-history note in the Interface dialog's extra panel, " +
		"set in a sentence about recording: an action, not a form field",
}

// stoggleRe finds the .stoggle panel however it is spelled: in a class
// attribute, alone or with a variant, or assigned as a className.
var stoggleRe = regexp.MustCompile(`class="stoggle[ "]|className = 'stoggle[ ']`)

var (
	ffTagRe     = regexp.MustCompile(`(?s)<(/?)([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(/?)>`)
	ffAttrRe    = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"`)
	ffCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)
	ffVoidTags  = map[string]bool{"input": true, "br": true, "hr": true, "img": true, "meta": true,
		"link": true, "source": true, "wbr": true, "area": true, "col": true, "embed": true, "param": true, "track": true}
	// ffParts are the classes whose box the stylesheet owns outright.
	ffParts = []string{"ff", "sform-label", "sform-input", "ff-help", "ff-toggle"}
	// ffHideOnly is the one inline style a field part may carry: hidden until a
	// script shows it.
	ffHideOnly = regexp.MustCompile(`^\s*display\s*:\s*none\s*;?\s*$`)
)

type ffNode struct {
	tag     string
	attrs   map[string]string
	classes map[string]bool
	kids    []*ffNode
	parent  *ffNode
	line    int
}

func (n *ffNode) has(c string) bool { return n.classes[c] }

func (n *ffNode) within(c string) bool {
	for p := n.parent; p != nil; p = p.parent {
		if p.has(c) {
			return true
		}
	}
	return false
}

// ffParse builds a tree from one of web/src/ui's templates. A tag scanner
// rather than an HTML parser: the templates are this repository's own, written
// as well-formed markup, and a parser would be a dependency for one test. A
// closing tag that closes nothing is reported, so a template it cannot read
// fails loudly instead of being scanned wrong.
func ffParse(t *testing.T, name, src string) *ffNode {
	t.Helper()
	src = ffCommentRe.ReplaceAllStringFunc(src, func(c string) string {
		return strings.Repeat("\n", strings.Count(c, "\n")) // keep line numbers
	})
	root := &ffNode{tag: "#root", classes: map[string]bool{}}
	cur := root
	for _, m := range ffTagRe.FindAllStringSubmatchIndex(src, -1) {
		closing, tag := src[m[2]:m[3]] == "/", strings.ToLower(src[m[4]:m[5]])
		line := strings.Count(src[:m[0]], "\n") + 1
		if closing {
			for p := cur; ; p = p.parent {
				if p == nil {
					t.Errorf("%s:%d: </%s> closes nothing open", name, line, tag)
					break
				}
				if p.tag == tag {
					cur = p.parent
					break
				}
			}
			continue
		}
		n := &ffNode{tag: tag, attrs: map[string]string{}, classes: map[string]bool{}, parent: cur, line: line}
		for _, a := range ffAttrRe.FindAllStringSubmatch(src[m[6]:m[7]], -1) {
			n.attrs[strings.ToLower(a[1])] = a[2]
		}
		for _, c := range strings.Fields(n.attrs["class"]) {
			n.classes[c] = true
		}
		cur.kids = append(cur.kids, n)
		if !ffVoidTags[tag] && src[m[8]:m[9]] != "/" {
			cur = n
		}
	}
	return root
}

func ffInCell(n *ffNode) bool {
	for p := n.parent; p != nil; p = p.parent {
		if p.tag == "td" {
			return true
		}
	}
	return false
}

func ffWalk(n *ffNode, fn func(*ffNode)) {
	fn(n)
	for _, k := range n.kids {
		ffWalk(k, fn)
	}
}

func TestDialogFieldsFollowTheContract(t *testing.T) {
	root := repoRoot(t)
	files := readFiles(t, root, "web/src/ui/", func(rel string) bool { return strings.HasSuffix(rel, ".html") })
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	exceptionsSeen := map[string]bool{}
	dialogs := 0
	for _, name := range names {
		ffWalk(ffParse(t, name, files[name]), func(n *ffNode) {
			if n.has("rtr-modal") {
				dialogs++
			}
			if !n.has("rtr-modal") && !n.within("rtr-modal") {
				return
			}
			at := name + ":" + strconv.Itoa(n.line)

			if n.has("stoggle") {
				t.Errorf("%s: a dialog toggle is an .ff field with .ff-toggle, not the Settings page's .stoggle panel", at)
			}
			for _, c := range ffParts {
				if st, ok := n.attrs["style"]; ok && n.has(c) && !ffHideOnly.MatchString(st) {
					t.Errorf("%s: .%s carries style=%q; a field's spacing and size belong to the stylesheet", at, c, st)
					break
				}
			}
			// A location search keeps its suggestion list as an extra child: it is
			// absolutely positioned, so it takes no row and the shape holds.
			var kids []*ffNode
			for _, k := range n.kids {
				if !k.has("cpick-list") {
					kids = append(kids, k)
				}
			}
			if n.has("ff") && (len(kids) != 3 || !kids[0].has("sform-label") || !kids[2].has("ff-help")) {
				t.Errorf("%s: an .ff is exactly a .sform-label, its control, and an .ff-help (empty is fine)", at)
			}

			switch n.tag {
			case "input", "select", "textarea":
			default:
				return
			}
			typ := strings.ToLower(n.attrs["type"])
			if typ == "hidden" || typ == "file" {
				return
			}
			if key := name + "#" + n.attrs["id"]; dialogControlExceptions[key] != "" {
				exceptionsSeen[key] = true
				return
			}
			if typ == "checkbox" || typ == "radio" {
				if !n.within("ff-toggle") && !n.within("ff-multi") {
					t.Errorf("%s: a %s in a dialog is an .ff-toggle or part of an .ff-multi", at, typ)
				}
				return
			}
			if !n.has("sform-input") {
				t.Errorf("%s: a dialog %s is an .sform-input", at, n.tag)
			}
			// A cell of a data-entry table is labelled by its column header.
			if !n.within("ff") && !ffInCell(n) {
				t.Errorf("%s: a dialog %s sits in an .ff field", at, n.tag)
			}
		})
	}
	if dialogs < 10 {
		t.Fatalf("found %d dialogs in web/src/ui - the scan has stopped seeing them", dialogs)
	}
	for key := range dialogControlExceptions {
		if !exceptionsSeen[key] {
			t.Errorf("%s is recorded as an exception but is no longer a control in a dialog - remove it", key)
		}
	}
}

// THE TYPESCRIPT HALF: field markup built in code obeys the same rules.
func TestFieldMarkupInTypeScriptCarriesNoInlineStyle(t *testing.T) {
	root := repoRoot(t)
	files := readFiles(t, root, "web/src/", func(rel string) bool {
		return strings.HasSuffix(rel, ".ts") && !strings.HasPrefix(rel, "web/src/gen/") && !isTestSource(rel)
	})
	// A class attribute naming a field part, with a style attribute in the same
	// tag, in either order.
	part := `(?:ff|ff-help|ff-toggle|sform-label)`
	styled := []*regexp.Regexp{
		regexp.MustCompile(`class="(?:[^"]* )?` + part + `(?: [^"]*)?"[^>]*\sstyle="`),
		regexp.MustCompile(`style="[^"]*"[^>]*\sclass="(?:[^"]* )?` + part + `(?: [^"]*)?"`),
		// A control may be placed in a row (flex, width, margin) but its height,
		// padding and type are the stylesheet's, or one box drifts off the rest.
		regexp.MustCompile(`class="(?:[^"]* )?sform-input(?: [^"]*)?"[^>]*\sstyle="[^"]*(?:height|padding|font)`),
	}
	stoggleSeen := map[string]bool{}
	for rel, src := range files {
		for _, re := range styled {
			for _, m := range re.FindAllStringIndex(src, -1) {
				t.Errorf("%s:%d: a field part carries an inline style - size and spacing belong to the stylesheet",
					rel, strings.Count(src[:m[0]], "\n")+1)
			}
		}
		if stoggleRe.MatchString(src) {
			if _, ok := stoggleFiles[rel]; !ok {
				t.Errorf("%s draws the Settings page's .stoggle panel; a dialog toggle is toggleHtml() from web/src/form.ts", rel)
			}
			stoggleSeen[rel] = true
		}
	}
	for rel := range stoggleFiles {
		if !stoggleSeen[rel] {
			t.Errorf("%s is recorded as drawing .stoggle on a page but no longer does - remove it from stoggleFiles", rel)
		}
	}
}

// THE STYLESHEET'S HALF: one control height, the subgrid, the themed placeholder.
func TestFormFieldStylesheetContract(t *testing.T) {
	css := mustRead(t, filepath.Join(repoRoot(t), "web", "public", "app.css"))
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(css, " ")
	for _, want := range []struct{ re, why string }{
		{`--ctl-h: [0-9.]+rem`, "--ctl-h, the one control height, is defined"},
		{`\.sform-input\{[^}]*height:var\(--ctl-h\)`, ".sform-input is --ctl-h tall"},
		{`\.ff-toggle \{[^}]*height: var\(--ctl-h\)`, "a toggle box is --ctl-h tall, like an input"},
		{`\.ff \{[^}]*grid-template-rows: subgrid;[^}]*grid-row: span 3`, "an .ff is a three-row subgrid, so rows align"},
		{`\.sform-input::placeholder\{color:var\(--text-muted\)`, "placeholders take the palette's muted text, not the browser's grey"},
		{`select\.sform-input\{appearance:none`, "a select is drawn by the stylesheet, not the browser"},
	} {
		if !regexp.MustCompile(want.re).MatchString(flat) {
			t.Errorf("app.css no longer holds the form contract: %s (looked for /%s/)", want.why, want.re)
		}
	}
}
