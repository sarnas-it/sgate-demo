package dast

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

type scannerLockEntry struct {
	ID      string `json:"id"`
	Image   string `json:"image"`
	License string `json:"license"`
	Source  string `json:"source"`
}

var scannerDigestRE = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

func TestScannerCatalogConsistency(t *testing.T) {
	cfg, err := LoadScanners("../../../dast/scanners.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../../dast/scanners.lock")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Scanners []scannerLockEntry `json:"scanners"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	byID := map[string]scannerLockEntry{}
	for _, e := range lock.Scanners {
		byID[e.ID] = e
	}
	for _, s := range cfg.Scanners {
		if !scannerDigestRE.MatchString(s.Image) {
			t.Errorf("%s: image not pinned by digest: %s", s.ID, s.Image)
		}
		e, ok := byID[s.ID]
		if !ok {
			t.Errorf("%s: missing in scanners.lock", s.ID)
			continue
		}
		if e.Image != s.Image {
			t.Errorf("%s: lock image %s != config %s", s.ID, e.Image, s.Image)
		}
		if e.License == "" || !strings.HasPrefix(e.Source, "https://") {
			t.Errorf("%s: incomplete catalog entry: %+v", s.ID, e)
		}
		if !strings.HasPrefix(s.Output, s.Workdir+"/") {
			t.Errorf("%s: output %s not under workdir %s", s.ID, s.Output, s.Workdir)
		}
		switch s.Format {
		case "zap-json", "nuclei-jsonl", "ferox-json":
		default:
			t.Errorf("%s: unexpected format %q", s.ID, s.Format)
		}
		if s.Network == "" {
			t.Errorf("%s: network empty", s.ID)
		}
	}
}
