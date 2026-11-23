package sarif

import "testing"

func TestParseBanditJSON(t *testing.T) {
	got, err := ParseBanditJSON("../../testdata/bandit.json", "bandit")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d", len(got))
	}
	if got[0].Severity != "high" || got[0].RuleID != "B602" || got[0].Line != 5 {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].File != "app.py" || got[1].Severity != "medium" {
		t.Errorf("second = %+v", got[1])
	}
	if got[0].Fingerprint == "" {
		t.Error("empty fingerprint")
	}
}
