package rules

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Read the shipped rule, rather than duplicating its regexp. The contract is
// Unicode White_Space, not whether an account name has a visible glyph.
func TestPR109ForeignAccountIdentityMatchesUnicodeIsSpace(t *testing.T) {
	account, err := LoadFile("../../../rules/proxy-foreign-account.yml")
	if err != nil {
		t.Fatal(err)
	}
	event := &model.Event{
		Action: "proxy.access", Outcome: "success", ActorKind: "user",
		Node: "portal.example", Attrs: map[string]string{"country": "DE"},
	}
	var spaces strings.Builder
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		event.ActorName = string(r)
		want := !unicode.IsSpace(r)
		if got := account.Match(event); got != want {
			t.Fatalf("actor U+%04X: match=%t, want %t (!unicode.IsSpace)", r, got, want)
		}
		if !want {
			spaces.WriteRune(r)
		}
	}
	blank := spaces.String()
	for _, actor := range []string{"", blank, blank + blank, blank + "alice" + blank, blank + "Иван" + blank, "Alice" + blank + "Smith"} {
		event.ActorName = actor
		want := strings.TrimSpace(actor) != ""
		if got := account.Match(event); got != want {
			t.Errorf("actor=%q: match=%t, want %t", actor, got, want)
		}
	}

	// These format characters, fillers and marks are not White_Space. Keep
	// their acceptance explicit, including when surrounded by actual spaces.
	for _, r := range []rune{
		0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180e,
		0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202e, 0x2060,
		0x2066, 0x2069, 0x3164, 0xfeff, 0xffa0, 0xe0001, 0xe0100,
	} {
		t.Run(fmt.Sprintf("nonspace_U+%04X", r), func(t *testing.T) {
			if unicode.IsSpace(r) {
				t.Fatalf("fixture U+%04X must not be White_Space", r)
			}
			event.ActorName = blank + string(r) + blank
			if !account.Match(event) {
				t.Errorf("non-White_Space account U+%04X must retain the account signal", r)
			}
		})
	}
}
