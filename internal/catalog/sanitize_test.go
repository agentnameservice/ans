package catalog

import "testing"

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"clean ascii unchanged", "Acme Support Agent", "Acme Support Agent"},
		{"clean unicode letters unchanged", "café résumé", "café résumé"},
		{"em dash unchanged", "a—b", "a—b"},
		{"emoji unchanged", "agent \U0001F916 ok", "agent \U0001F916 ok"},
		{"strips bidi override U+202E", "abc\u202edef", "abcdef"},
		{"strips bidi isolates U+2066-2069", "a\u2066b\u2067c\u2068d\u2069e", "abcde"},
		{"strips zero-width space/joiner", "a\u200bb\u200cc\u200dd", "abcd"},
		{"strips BOM/zero-width-nbsp U+FEFF", "a\ufeffb", "ab"},
		{"strips NUL", "a\x00b", "ab"},
		{"strips C0 control", "a\x07b\x1bc", "abc"},
		{"strips tab and newline (Cc)", "a\tb\nc", "abc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeText(tc.in); got != tc.want {
				t.Errorf("sanitizeText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeTags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty slice", []string{}, nil},
		{"dedupe preserves first-seen order", []string{"b", "a", "b", "c", "a"}, []string{"b", "a", "c"}},
		{"drops tags that sanitize to empty", []string{"\u200b", "ok", "\x00"}, []string{"ok"}},
		{"all empty after sanitize -> nil", []string{"\u202e", "\ufeff"}, nil},
		{"sanitizes within a tag", []string{"sa\u202efe"}, []string{"safe"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTags(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("sanitizeTags(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("sanitizeTags(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
