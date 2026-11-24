package sarif

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePHPStanJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phpstan.json")
	raw := `{"files":{"/app/app.php":{"messages":[{"message":"Variable $undefined might not be defined.","line":3,"identifier":"variable.undefined"}]}}}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ParsePHPStanJSON(path, "phpstan")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].File != "app.php" || got[0].Line != 3 || got[0].Severity != "medium" {
		t.Fatalf("got %+v", got)
	}
}
