package verify

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ONE TABLE DENSITY.
//
// Every table has one cell padding, one row height and one header, set once in
// app.css's TABLES section. Before it there were fifteen paddings and seven
// header sizes, and the documented .66rem header lost to Tabler's .75rem on
// most of the app, because Tabler's selectors outranked every rule written to
// correct them. The section wins by specificity now; this keeps anything else
// from sizing a cell, in the stylesheet or in the markup.

// tableDensityProp is what the TABLES section owns on a cell. Colour, weight,
// alignment, width and borders stay free: a column may be muted, bold, right
// aligned or narrow without changing the table's rhythm.
var tableDensityProp = regexp.MustCompile(`(?i)(?:^|[;"\s])(padding(?:-[a-z]+)?|font-size|font-family|line-height|height|letter-spacing|text-transform)\s*:`)

// A selector whose subject is a cell or a table: `.x td`, `.x th.y`, `.x td:first-child`.
var tableSubjectRe = regexp.MustCompile(`(?:^|[\s>+~])(?:td|th|table)(?:[.:\[#][^\s>+~]*)?$`)

func TestTablesHaveOneDensity(t *testing.T) {
	root := repoRoot(t)
	appCSS := mustRead(t, filepath.Join(root, "web", "public", "app.css"))
	flat := regexp.MustCompile(`\s+`).ReplaceAllString(appCSS, " ")
	for _, want := range []struct{ re, why string }{
		{`--tbl-pad-y:[0-9.]+rem;--tbl-pad-x:[0-9.]+rem;--tbl-row-h:[0-9.]+rem`, "the three table tokens are defined"},
		{`html:root table td\{padding:var\(--tbl-pad-y\) var\(--tbl-pad-x\);height:var\(--tbl-row-h\)`, "a cell takes the tokens"},
		{`html:root table th\{padding:var\(--tbl-pad-y\) var\(--tbl-pad-x\);font-family:var\(--font-ui\);font-size:\.66rem`, "a header is the documented .66rem"},
		{`html:root table td\.tbl-empty\{`, "an empty table has one empty-state cell"},
	} {
		if !regexp.MustCompile(want.re).MatchString(flat) {
			t.Errorf("app.css no longer holds the table contract: %s (looked for /%s/)", want.why, want.re)
		}
	}

	comment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	rule := regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	css := readFiles(t, root, "web/public/", func(rel string) bool {
		return strings.HasSuffix(rel, ".css") && !strings.Contains(rel, "/vendor/")
	})
	for rel, src := range css {
		src = comment.ReplaceAllStringFunc(src, func(c string) string { return strings.Repeat("\n", strings.Count(c, "\n")) })
		for _, m := range rule.FindAllStringSubmatchIndex(src, -1) {
			sel := strings.TrimSpace(src[m[2]:m[3]])
			if strings.HasPrefix(sel, "html:root table") {
				continue // the TABLES section, exceptions included
			}
			cell := false
			for _, s := range strings.Split(sel, ",") {
				if tableSubjectRe.MatchString(strings.TrimSpace(s)) {
					cell = true
				}
			}
			if !cell {
				continue
			}
			if p := tableDensityProp.FindStringSubmatch(src[m[4]:m[5]]); p != nil {
				t.Errorf("%s:%d: %s sets %s on a table or cell - density is the TABLES section's; an exception belongs there, with its reason",
					rel, strings.Count(src[:m[4]], "\n")+1, sel, p[1])
			}
		}
	}

	markup := readFiles(t, root, "web/src/", func(rel string) bool {
		return (strings.HasSuffix(rel, ".html") || strings.HasSuffix(rel, ".ts")) &&
			!strings.HasPrefix(rel, "web/src/gen/") && !isTestSource(rel)
	})
	cellTag := regexp.MustCompile(`<t[dh][\s>][^<>]*`)
	styleAttr := regexp.MustCompile(`style="([^"]*)"`)
	tableSm := regexp.MustCompile(`class="(?:[^"]* )?table-sm[ "]`)
	for rel, src := range markup {
		for _, m := range cellTag.FindAllStringIndex(src, -1) {
			for _, s := range styleAttr.FindAllStringSubmatch(src[m[0]:m[1]], -1) {
				if p := tableDensityProp.FindStringSubmatch(`"` + s[1]); p != nil {
					t.Errorf("%s:%d: a cell's inline style sets %s - the table sets it; an empty state is .tbl-empty, a child row .tbl-indent, a checkbox column .tbl-pick",
						rel, strings.Count(src[:m[0]], "\n")+1, p[1])
				}
			}
		}
		for _, m := range tableSm.FindAllStringIndex(src, -1) {
			t.Errorf("%s:%d: Tabler's .table-sm is a second density - every table has the one", rel, strings.Count(src[:m[0]], "\n")+1)
		}
	}
}
