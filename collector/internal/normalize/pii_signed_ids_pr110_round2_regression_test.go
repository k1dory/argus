package normalize

import "testing"

// Исключение для международного префикса не должно возвращать поиск
// российской телефонной подстроки внутри целого идентификатора длиннее
// предела E.164 (15 цифр). Это регрессия относительно f8ab708: раньше всё
// такое число заменялось пробелом, независимо от знака.
func TestPR110Round2HasPIIRejectsOverlongSignedIDs(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"unsigned_id", "id=12800123456789012", false},
		{"signed_id_with_russian_substring", "id=+12800123456789012", false},
		{"signed_16_digit_id_starting_with_7", "id=+7123456789012345", false},
		{"signed_16_digit_id_starting_with_8", "id=+8001234567890123", false},
		{"international_13_digits", "phone=+4917612345678", true},
		{"international_15_digits", "phone=+491763312345678", true},
		{"real_phone_after_id", "id=+12800123456789012; phone=+4917612345678", true},
		{"real_phone_before_id", "phone=+4917612345678; id=+12800123456789012", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasPII(tc.text); got != tc.want {
				t.Errorf("HasPII(%q)=%v, want %v; a signed ID must not change the PII route", tc.text, got, tc.want)
			}
		})
	}
}
