package main

import "testing"

func TestIsExcluded(t *testing.T) {
	patterns := []string{"core/testdata/**", "fixtures/*.py"}
	cases := map[string]bool{
		"core/testdata/python-bandit/app.py": true,
		"core/testdata/semgrep.sarif":        true,
		"fixtures/a.py":                      true,
		"fixtures/sub/a.py":                  false,
		"sast/go/main.go":                    false,
	}
	for file, want := range cases {
		if got := isExcluded(file, patterns); got != want {
			t.Errorf("%s: got %v want %v", file, got, want)
		}
	}
}
