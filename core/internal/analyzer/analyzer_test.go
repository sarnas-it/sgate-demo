package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"code.sarnas.ru/sgate/internal/config"
)

func TestRunCommand(t *testing.T) {
	repo := t.TempDir()
	out := t.TempDir()
	src, err := os.ReadFile("../../testdata/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "fixture.sarif"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	spec := config.Analyzer{
		ID:      "fake",
		Runtime: "command",
		Command: []string{"sh", "-c", `cp "$SGATE_REPO/fixture.sarif" "$SGATE_OUT"`},
		Output:  "out.sarif",
		Timeout: "5s",
		Network: "none",
	}
	path, err := Run(context.Background(), spec, repo, repo, out, "")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(repo, "out.sarif") {
		t.Fatalf("path = %q", path)
	}
}

func TestLinkedGitRoot(t *testing.T) {
	base := t.TempDir()
	gitRoot := filepath.Join(base, ".git")
	wtDir := filepath.Join(base, "wt")
	if err := os.MkdirAll(filepath.Join(gitRoot, "worktrees", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wtDir, ".git"), []byte("gitdir: "+filepath.Join(gitRoot, "worktrees", "x")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := linkedGitRoot(wtDir)
	if !ok || got != gitRoot {
		t.Fatalf("got %q ok=%v, want %q", got, ok, gitRoot)
	}
	if _, ok := linkedGitRoot(t.TempDir()); ok {
		t.Fatal("normal dir must not be a linked worktree")
	}
}

// TestFailOnMarksZeroExitAsFailure — анализатор может отдать пустой отчёт с
// кодом 0, сообщив о сбое в выводе (gosec: «Golang errors in file»). Такой
// прогон обязан считаться сбоем, иначе «0 находок» — ложное отрицание.
func TestFailOnMarksZeroExitAsFailure(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:      "fake",
		Runtime: "command",
		Command: []string{"sh", "-c", `printf '{}' > "$SGATE_OUT"; echo "Golang errors in file: [plugins/standard]" >&2`},
		Output:  "out.sarif",
		Timeout: "10s",
		FailOn:  []string{"Golang errors in file"},
	}
	if _, err := Run(context.Background(), spec, out, out, out, ""); err == nil {
		t.Fatal("ожидалась ошибка: анализатор сообщил о сбое сборки")
	}
}

func TestFailOnAllowsCleanOutput(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:      "fake",
		Runtime: "command",
		Command: []string{"sh", "-c", `printf '{}' > "$SGATE_OUT"`},
		Output:  "out.sarif",
		Timeout: "10s",
		FailOn:  []string{"Golang errors in file"},
	}
	if _, err := Run(context.Background(), spec, out, out, out, ""); err != nil {
		t.Fatalf("чистый прогон не должен падать: %v", err)
	}
}

// TestScannedRegexMarksEmptyRunAsFailure — анализатор может отдать пустой отчёт
// с кодом 0, не напечатав ни одной строки прогресса: gosec при ошибке
// тулчейна/сети делает именно так. Без проверки покрытия это «0 находок».
func TestScannedRegexMarksEmptyRunAsFailure(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:              "fake",
		Runtime:         "command",
		Command:         []string{"sh", "-c", `printf '{"runs":[]}' > "$SGATE_OUT"`},
		Output:          "out.sarif",
		Timeout:         "10s",
		ScannedRegex:    `Checking file: (\S+)`,
		MinScannedFiles: 1,
	}
	if _, err := Run(context.Background(), spec, out, out, out, ""); err == nil {
		t.Fatal("ожидалась ошибка: ни одного просканированного файла")
	}
}

func TestScannedRegexCountsUniqueFiles(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:      "fake",
		Runtime: "command",
		Command: []string{"sh", "-c", `printf '{"runs":[]}' > "$SGATE_OUT";
			echo "Checking file: /src/a.go"; echo "Checking file: /src/a.go"; echo "Checking file: /src/b.go" >&2`},
		Output:          "out.sarif",
		Timeout:         "10s",
		ScannedRegex:    `Checking file: (\S+)`,
		MinScannedFiles: 2,
	}
	res, err := RunDetailed(context.Background(), spec, out, out, out, "")
	if err != nil {
		t.Fatalf("прогон с прогрессом не должен падать: %v", err)
	}
	if res.ScannedFiles != 2 {
		t.Fatalf("ScannedFiles = %d, want 2 (уникальные файлы)", res.ScannedFiles)
	}
}

func TestScannedRegexBelowMinimumFails(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:              "fake",
		Runtime:         "command",
		Command:         []string{"sh", "-c", `printf '{"runs":[]}' > "$SGATE_OUT"; echo "Checking file: /src/a.go"`},
		Output:          "out.sarif",
		Timeout:         "10s",
		ScannedRegex:    `Checking file: (\S+)`,
		MinScannedFiles: 5,
	}
	if _, err := Run(context.Background(), spec, out, out, out, ""); err == nil {
		t.Fatal("ожидалась ошибка: файлов меньше минимума")
	}
}

// TestRequireArtifactsRejectsEmptyReport — второй, независимый признак
// полноты: semgrep всегда пишет artifacts, и пустой список значит, что
// анализатор не открыл ни одного файла.
func TestRequireArtifactsRejectsEmptyReport(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:               "fake",
		Runtime:          "command",
		Command:          []string{"sh", "-c", `printf '{"runs":[{"results":[],"artifacts":[]}]}' > "$SGATE_OUT"`},
		Output:           "out.sarif",
		Timeout:          "10s",
		RequireArtifacts: true,
	}
	if _, err := Run(context.Background(), spec, out, out, out, ""); err == nil {
		t.Fatal("ожидалась ошибка: artifacts пуст")
	}
}

func TestRequireArtifactsAcceptsNonEmpty(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:               "fake",
		Runtime:          "command",
		Command:          []string{"sh", "-c", `printf '{"runs":[{"results":[],"artifacts":[{"location":{"uri":"a.go"}},{"location":{"uri":"b.go"}}]}]}' > "$SGATE_OUT"`},
		Output:           "out.sarif",
		Timeout:          "10s",
		RequireArtifacts: true,
	}
	res, err := RunDetailed(context.Background(), spec, out, out, out, "")
	if err != nil {
		t.Fatalf("непустые artifacts не должны падать: %v", err)
	}
	if res.ScannedFiles != 2 {
		t.Fatalf("ScannedFiles = %d, want 2", res.ScannedFiles)
	}
}

// TestNoCoverageChecksKeepsOldBehaviour — без новых полей поведение прежнее.
func TestNoCoverageChecksKeepsOldBehaviour(t *testing.T) {
	out := t.TempDir()
	spec := config.Analyzer{
		ID:      "fake",
		Runtime: "command",
		Command: []string{"sh", "-c", `printf '{"runs":[]}' > "$SGATE_OUT"`},
		Output:  "out.sarif",
		Timeout: "10s",
	}
	if _, err := Run(context.Background(), spec, out, out, out, ""); err != nil {
		t.Fatalf("без проверок покрытия пустой отчёт допустим: %v", err)
	}
}
