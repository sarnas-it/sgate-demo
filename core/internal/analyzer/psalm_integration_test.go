package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Запускается только с SGATE_INTEGRATION=1: нужен Docker и образ Psalm.
func TestPsalmAdapter(t *testing.T) {
	if os.Getenv("SGATE_INTEGRATION") == "" {
		t.Skip("set SGATE_INTEGRATION=1 to run Docker integration")
	}
	repo, err := filepath.Abs("../../testdata/php-psalm")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	spec := config.Analyzer{
		ID:            "psalm",
		Runtime:       "docker",
		Image:         "ghcr.io/psalm/psalm:latest",
		Entrypoint:    "psalm",
		Workdir:       "/src",
		Command:       []string{"--no-cache", "--output-format=sarif", "--taint-analysis"},
		Output:        "/out/psalm.sarif",
		Format:        "sarif",
		ExitCodes:     []int{0, 1, 2},
		CaptureStdout: true,
		Timeout:       "2m",
		Network:       "none",
	}
	path, err := Run(context.Background(), spec, repo, repo, out, "0:0")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := sarif.ParseFile(path, "psalm", spec.Format)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("psalm found nothing in fixture")
	}
	t.Logf("psalm: %s %s:%d %s", findings[0].RuleID, findings[0].File, findings[0].Line, findings[0].Severity)
}
