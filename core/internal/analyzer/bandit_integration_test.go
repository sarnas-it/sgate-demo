package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Запускается только с SGATE_INTEGRATION=1: нужен Docker и образ Bandit.
func TestBanditAdapter(t *testing.T) {
	if os.Getenv("SGATE_INTEGRATION") == "" {
		t.Skip("set SGATE_INTEGRATION=1 to run Docker integration")
	}
	repo, err := filepath.Abs("../../testdata/python-bandit")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	spec := config.Analyzer{
		ID:      "bandit",
		Runtime: "docker",
		Image:   "cytopia/bandit:1",
		Workdir: "/src",
		Command: []string{"-r", ".", "-f", "json", "-o", "/out/bandit.json", "-q"},
		Output:  "/out/bandit.json",
		Format:  "bandit-json",
		Timeout: "2m",
		Network: "none",
	}
	path, err := Run(context.Background(), spec, repo, repo, out, "0:0")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := sarif.ParseFile(path, "bandit", spec.Format)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("bandit found nothing in fixture")
	}
	t.Logf("bandit: %s %s:%d %s", findings[0].RuleID, findings[0].File, findings[0].Line, findings[0].Severity)
}
