package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Запускается только с SGATE_INTEGRATION=1: нужен Docker и образ gosec.
func TestGosecAdapter(t *testing.T) {
	if os.Getenv("SGATE_INTEGRATION") == "" {
		t.Skip("set SGATE_INTEGRATION=1 to run Docker integration")
	}
	repo, err := filepath.Abs("../../testdata/go-gosec")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	spec := config.Analyzer{
		ID:      "gosec",
		Runtime: "docker",
		Image:   "securego/gosec:2.24.6",
		Command: []string{"-fmt=sarif", "-out=/out/gosec.sarif", "./..."},
		Workdir: "/src",
		Output:  "/out/gosec.sarif",
		Timeout: "2m",
		Network: "none",
		Env:     map[string]string{"GOCACHE": "/tmp/gocache", "GOMODCACHE": "/tmp/gomodcache"},
	}
	path, err := Run(context.Background(), spec, repo, repo, out, "0:0")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := sarif.Parse(path, "gosec")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("gosec found nothing in fixture")
	}
	t.Logf("gosec: %s %s:%d %s", findings[0].RuleID, findings[0].File, findings[0].Line, findings[0].Severity)
}
