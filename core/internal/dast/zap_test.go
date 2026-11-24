package dast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseZAPJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zap.json")
	raw := `{"site":[{"@name":"http://127.0.0.1:3000","alerts":[{"pluginid":"10021","alert":"X-Content-Type-Options","riskcode":"2","desc":"missing header","instances":[{"uri":"http://127.0.0.1:3000/","method":"GET","param":""}]},{"pluginid":"10038","alert":"CSP","riskcode":"3","desc":"no CSP","instances":[]}]}]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ParseZAPJSON(path, "zap")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d", len(got))
	}
	if got[0].Severity != "medium" || got[0].File != "http://127.0.0.1:3000/" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Severity != "high" {
		t.Errorf("second = %+v", got[1])
	}
}
