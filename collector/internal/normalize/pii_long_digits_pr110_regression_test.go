package normalize

import "testing"

// PR #110 исключает подстроки внутри длинных идентификаторов, но номер с
// явным международным префиксом может содержать до 15 цифр. Такие номера
// должны по-прежнему включать запрет облачного маршрута по флагу PII.
func TestPR110HasPIIPreservesInternationalPhones(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"twelve_digits", "+441632960961", true},
		{"thirteen_digits", "+4917612345678", true},
		{"fourteen_digits", "+49123456789012", true},
		{"fifteen_digits", "+491763312345678", true},
		{"formatted_thirteen_digits", "+49 176 12345678", true},
		{"milliseconds", "rt=1780000000000", false},
		{"phone_shaped_substring_in_id", "id=12800123456789012", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasPII(tc.text); got != tc.want {
				t.Errorf("HasPII(%q) = %v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

// Замена длинного числа не должна скрывать отдельный телефон рядом с ним.
// PAN и СНИЛС здесь — соседние поля; отдельные детекторы этих типов не входят
// в контракт HasPII (email/phone).
func TestPR110HasPIIPreservesPhonesBesideNumericFields(t *testing.T) {
	for _, phone := range []string{
		"+79211234567", "89211234567", "+7 (921) 123-45-67",
		"+441632960961", "+4917612345678",
	} {
		for _, adjacent := range []struct{ name, value string }{
			{"timestamp", "rt=1780000000000"},
			{"card", "card=4111111111111111"},
			{"snils", "snils=112-233-445 95"},
		} {
			for _, sep := range []string{" ", ",", ";", "|", "\t", "\n"} {
				t.Run(phone+"/"+adjacent.name+"/"+sep, func(t *testing.T) {
					for _, text := range []string{adjacent.value + sep + phone, phone + sep + adjacent.value} {
						if !HasPII(text) {
							t.Errorf("separate phone lost beside numeric field: %q", text)
						}
					}
				})
			}
		}
	}
}
