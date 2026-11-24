package dast

import "testing"

func TestNormalizeCWE(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"79", "CWE-79"},
		{"CWE-79", "CWE-79"},
		{[]any{"89"}, "CWE-89"},
		{"0", ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := normalizeCWE(c.in); got != c.want {
			t.Errorf("%v: got %q want %q", c.in, got, c.want)
		}
	}
}
