package verify

import (
	"regexp"
	"strings"
	"testing"
)

// ONE CORNER SCALE, ONE SET OF FONTS.
//
// Corners were 24 values, from 1px to 20px with 7, 8, 9, 11, 14 and 15
// between, so two boxes doing one job were rounded differently. They are seven
// now, by role (DESIGN.md, Shapes): 2px a thin bar, 4px a small thing (a key,
// a checkbox, a pill, a chip, a count), 6px a control or a box inside a card,
// 10px a card or a floating panel, 12px a modal, 50% a dot, 999px a capsule.
// The check holds the values; which of them an element takes is the role table.
//
// Fonts come from the tokens: --font-ui, --font-mono and --font-brand (the
// wordmark), in CSS as var(), in a canvas or a chart through monoFont() in
// web/src/palette.ts. A family written out by name skips the token, so a page
// drew the diff view in the system's monospace and the About wordmark in a
// face Branding could not reach.

var cornerScale = map[string]bool{"0": true, "2px": true, "4px": true, "6px": true, "10px": true, "12px": true, "50%": true, "999px": true}

var (
	cssComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssRadius   = regexp.MustCompile(`border-radius\s*:\s*([^;}"']+)`)
	tsRadius    = regexp.MustCompile(`borderRadius\s*=\s*['"]([^'"]*)['"]`)
	fontFace    = regexp.MustCompile(`(?s)@font-face\s*\{[^}]*\}`)
	cssFamily   = regexp.MustCompile(`font-family\s*:\s*([^;}"]+)`)
	tsFamily    = regexp.MustCompile(`(?:family\s*:\s*["']|fontFamily\s*=\s*["']|\.font\s*=\s*["'][^"'\n]*\dpx\s+['"]?[A-Za-z])[^"'\n]*`)
	fontTokenOK = regexp.MustCompile(`^(?:var\(--font-[a-z]+\)|inherit)$`)
)

// blankComments keeps line numbers while hiding comments from a scan.
func blankComments(src string, re *regexp.Regexp) string {
	return re.ReplaceAllStringFunc(src, func(c string) string { return strings.Repeat("\n", strings.Count(c, "\n")) })
}

func webStyleSources(t *testing.T, root string) map[string]string {
	return readFiles(t, root, "web/", func(rel string) bool {
		return (strings.HasSuffix(rel, ".css") || strings.HasSuffix(rel, ".html") || strings.HasSuffix(rel, ".ts")) &&
			!strings.Contains(rel, "/vendor/") && !strings.Contains(rel, "/node_modules/") &&
			!strings.HasPrefix(rel, "web/src/gen/") && !strings.HasPrefix(rel, "web/test/")
	})
}

func TestCornersAreOnTheScale(t *testing.T) {
	for rel, src := range webStyleSources(t, repoRoot(t)) {
		src = blankComments(src, cssComment)
		check := func(i int, v string) {
			v = strings.TrimSpace(strings.Replace(v, "!important", "", 1))
			for _, part := range strings.Fields(v) {
				if !cornerScale[part] {
					t.Errorf("%s:%d: border-radius %s is off the scale - 2px bar, 4px small, 6px control or inner box, 10px card, 12px modal, 50%% dot, 999px capsule (DESIGN.md, Shapes)", rel, lineOf(src, i), v)
					return
				}
			}
		}
		for _, m := range cssRadius.FindAllStringSubmatchIndex(src, -1) {
			check(m[0], src[m[2]:m[3]])
		}
		for _, m := range tsRadius.FindAllStringSubmatchIndex(src, -1) {
			check(m[0], src[m[2]:m[3]])
		}
	}
}

func TestFontsAreTheTokens(t *testing.T) {
	for rel, src := range webStyleSources(t, repoRoot(t)) {
		// The catalogue of fonts Branding offers names each family on purpose.
		if rel == "web/src/branding.ts" {
			continue
		}
		src = blankComments(src, cssComment)
		// A @font-face declares a family; it is where a name belongs.
		src = blankComments(src, fontFace)
		for _, m := range cssFamily.FindAllStringSubmatchIndex(src, -1) {
			v := strings.TrimSpace(strings.Replace(src[m[2]:m[3]], "!important", "", 1))
			if !fontTokenOK.MatchString(v) {
				t.Errorf("%s:%d: font-family %s names a font - use var(--font-ui), var(--font-mono) or var(--font-brand)", rel, lineOf(src, m[0]), v)
			}
		}
		if strings.HasSuffix(rel, ".ts") {
			for _, m := range tsFamily.FindAllStringIndex(src, -1) {
				t.Errorf("%s:%d: %s names a font - a canvas or chart takes monoFont() from web/src/palette.ts", rel, lineOf(src, m[0]), src[m[0]:m[1]])
			}
		}
	}
}
