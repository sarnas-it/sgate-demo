package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLanguages(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"a.go", "b.php", "web/c.tsx", "node_modules/x.go", "vendor/y.go"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	langs, err := Languages(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"go", "php", "typescript"} {
		if !langs[want] {
			t.Errorf("missing language %q: %v", want, langs)
		}
	}
	if langs["javascript"] {
		t.Errorf("node_modules/vendor must be skipped: %v", langs)
	}
}
