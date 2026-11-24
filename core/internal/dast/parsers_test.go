package dast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNuclei(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.jsonl")
	raw := `{"template-id":"CVE-2024-1","info":{"name":"RCE","severity":"critical","classification":{"cwe-id":["89"]}},"host":"http://x","matched-at":"http://x/a","matcher-name":"rce"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ParseNucleiJSONL(path, "nuclei")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v err %v", got, err)
	}
	if got[0].Severity != "critical" || got[0].RuleID != "CVE-2024-1" || got[0].CWE != "CWE-89" {
		t.Errorf("got %+v", got[0])
	}
}

func TestParseFerox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.jsonl")
	raw := `{"type":"response","url":"http://x/admin","status":200}` + "\n" + `{"type":"response","url":"http://x/missing","status":404}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ParseFeroxJSON(path, "ferox")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v err %v", got, err)
	}
	if got[0].File != "http://x/admin" || got[0].Severity != "info" {
		t.Errorf("got %+v", got[0])
	}
}
