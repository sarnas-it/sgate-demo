package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/sarif"
)

func TestPHPStanAdapter(t *testing.T) {
	if os.Getenv("SGATE_INTEGRATION") == "" {
		t.Skip("set SGATE_INTEGRATION=1 to run Docker integration")
	}
	repo, err := filepath.Abs("../../testdata/php-phpstan")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	spec := config.Analyzer{
		ID:            "phpstan",
		Runtime:       "docker",
		Image:         "ghcr.io/phpstan/phpstan@sha256:a37607d838fa6e25d1debdd0f774021c2be91248e74126c32283c3d6d2ed1a0b",
		Workdir:       "/src",
		Command:       []string{"analyse", "--error-format=json", "--no-progress", "--configuration=phpstan.neon"},
		Output:        "/out/phpstan.json",
		Format:        "phpstan-json",
		ExitCodes:     []int{0, 1},
		CaptureStdout: true,
		Timeout:       "2m",
		Network:       "none",
	}
	path, err := Run(context.Background(), spec, repo, repo, out, "0:0")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := sarif.ParseFile(path, "phpstan", spec.Format)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("phpstan found nothing in fixture")
	}
	t.Logf("phpstan: %s %s:%d %s", findings[0].RuleID, findings[0].File, findings[0].Line, findings[0].Severity)
}
