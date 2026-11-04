package model

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Эталон — strip из f372539, повторяемый до неподвижной точки. Входы короче
// MaxFieldLen: обрезку проверяем отдельно, чтобы не требовать сохранения
// промежуточной обрезки прежнего многошагового алгоритма на битом UTF-8.
func pr116PreviousStrip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == 0x1b:
			i += skipEscape(s[i:]) // skipEscape в проверяемом PR не менялся.
		case c == '\n' || c == '\r':
			b.WriteByte(' ')
			i++
		case c < 0x20 && c != '\t', c == 0x7f:
			i++
		case c == 0xc2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9f:
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

func TestPR116CleanMatchesPreviousFixedPoint(t *testing.T) {
	check := func(input string) {
		t.Helper()
		want := input
		for i := 0; i <= len(input); i++ {
			next := pr116PreviousStrip(want)
			if next == want {
				break
			}
			want = next
		}
		got, cut := Clean(input)
		if got != want || cut {
			t.Fatalf("Clean(%q) = (%q, %v), want (%q, false)", input, got, cut, want)
		}
		if again, cut := Clean(got); again != got || cut {
			t.Fatalf("Clean is not stable: input=%q first=%q second=%q cut=%v", input, got, again, cut)
		}
	}
	// Проверяем стыки фрагментов, в том числе разорванные ESC, управляющие
	// символы между C2/80 и печатные U+00A0/U+00A3, которые удалять нельзя.
	parts := []string{"a", "\xc2", "\x80", "\x9f", "\x00", "\x7f", "\n", "\r", "\t", "\x1b", "[31m", "\x1b[0m", "\x1b]x\x07", "\x1bPdata\x1b\\", "\u00a0£Я"}
	for _, a := range parts {
		for _, b := range parts {
			for _, c := range parts {
				check(a + b + c)
			}
		}
	}
	for _, depth := range []int{1, 2, 8, 32} {
		for continuation := byte(0x80); continuation <= 0x9f; continuation++ {
			for _, gap := range []string{"\x00", "\x7f", "\x1b[31m", "\x1b]title\x1b\\", "\t", "\n"} {
				check("a" + strings.Repeat("\xc2", depth) + gap + strings.Repeat(string([]byte{continuation}), depth) + "b")
			}
		}
	}
}

func TestPR116CleanEscapeSequences(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"CSI", "a\x1b[31mb\x1b[0mc", "abc"},
		{"OSC_BEL", "a\x1b]0;title\x07b", "ab"},
		{"OSC_ST", "a\x1b]0;title\x1b\\b", "ab"},
		{"DCS", "a\x1bPdata\x1b\\b", "ab"},
		{"APC", "a\x1b_data\x1b\\b", "ab"},
		{"PM", "a\x1b^data\x1b\\b", "ab"},
		{"two_byte", "a\x1b7b", "ab"},
		{"incomplete_CSI", "a\x1b[31", "a"},
		{"incomplete_OSC", "a\x1b]title", "a"},
		{"trailing_ESC", "a\x1b", "a"},
		{"nested_ESC", "a\x1b]title\x1b[31mb", "ab"},
		{"C1_around_CSI", "a\xc2\x1b[31m\x80b", "ab"},
		{"whitespace", "a\r\nb\tc", "a  b\tc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, cut := Clean(tc.input)
			if got != tc.want || cut {
				t.Fatalf("got (%q, %v), want (%q, false)", got, cut, tc.want)
			}
		})
	}
}

func TestPR116CleanRuneBoundaryAndRawEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, suffix, wantSuffix string
		prefix                   int
		cut                      bool
	}{
		{"exact_ASCII", "", "", MaxFieldLen, false},
		{"two_byte", "яZ", "", MaxFieldLen - 1, true},
		{"three_byte", "€Z", "", MaxFieldLen - 2, true},
		{"four_byte", "🙂Z", "", MaxFieldLen - 3, true},
		{"exact_rune", "🙂", "🙂", MaxFieldLen - 4, false},
		{"escape_before_cut", "\x1b[31mя\x1b[0m", "", MaxFieldLen - 1, true},
		{"joined_C1_before_cut", "\xc2\x00\x80я", "", MaxFieldLen - 1, true},
		{"invalid_UTF8_before_cut", "\xffZQ", "", MaxFieldLen - 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := strings.Repeat("a", tc.prefix)
			input, want := prefix+tc.suffix, prefix+tc.wantSuffix
			got, cut := Clean(input)
			if got != want || cut != tc.cut || !utf8.ValidString(got) {
				t.Fatalf("len=%d cut=%v valid=%v; want len=%d cut=%v", len(got), cut, utf8.ValidString(got), len(want), tc.cut)
			}
			e := Event{Raw: input, Object: input, Attrs: map[string]string{"payload": input}}
			e.Sanitize()
			if e.Raw != input || e.Object != want || e.Attrs["payload"] != want || (e.Attrs["truncated"] == "1") != tc.cut {
				t.Fatal("Sanitize changed raw evidence, field contents, or the truncation marker")
			}
		})
	}
}
