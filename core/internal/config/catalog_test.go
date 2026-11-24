package config

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

type lockEntry struct {
	ID      string `json:"id"`
	Image   string `json:"image"`
	License string `json:"license"`
	Source  string `json:"source"`
}

var digestRE = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

func TestCatalogConsistency(t *testing.T) {
	cfg, err := Load("../../analyzers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../analyzers.lock")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Analyzers []lockEntry `json:"analyzers"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	byID := map[string]lockEntry{}
	for _, e := range lock.Analyzers {
		byID[e.ID] = e
	}
	for _, a := range cfg.Analyzers {
		if !digestRE.MatchString(a.Image) {
			t.Errorf("%s: image not pinned by digest: %s", a.ID, a.Image)
		}
		e, ok := byID[a.ID]
		if !ok {
			t.Errorf("%s: missing in analyzers.lock", a.ID)
			continue
		}
		if e.Image != a.Image {
			t.Errorf("%s: lock image %s != config %s", a.ID, e.Image, a.Image)
		}
		if e.License == "" || !strings.HasPrefix(e.Source, "https://") {
			t.Errorf("%s: incomplete catalog entry: %+v", a.ID, e)
		}
		if !strings.HasPrefix(a.Output, "/out/") {
			t.Errorf("%s: docker output must be under /out: %s", a.ID, a.Output)
		}
		switch a.Format {
		case "sarif", "bandit-json", "phpstan-json":
		default:
			t.Errorf("%s: unexpected format %q", a.ID, a.Format)
		}
		if len(a.ExitCodes) == 0 {
			t.Errorf("%s: exit_codes empty", a.ID)
		}
	}
}
