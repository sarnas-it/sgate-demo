// Package analyzer запускает сменные SAST-анализаторы в песочнице.
package analyzer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.sarnas.ru/sgate/internal/config"
	"code.sarnas.ru/sgate/internal/sarif"
)

// Result — итог прогона анализатора: путь к отчёту и сколько файлов он
// реально открыл. Второе число нужно, чтобы «0 находок» не путалось с
// «анализатор ничего не просканировал» (ГОСТ Р 71207-2024, 8.8 — полнота).
type Result struct {
	Path         string
	ScannedFiles int
}

// Run запускает анализатор и возвращает путь к SARIF-файлу на хосте.
func Run(ctx context.Context, spec config.Analyzer, repo, configDir, outDir, user string) (string, error) {
	res, err := RunDetailed(ctx, spec, repo, configDir, outDir, user)
	return res.Path, err
}

// RunDetailed — Run вместе с числом просканированных файлов.
func RunDetailed(ctx context.Context, spec config.Analyzer, repo, configDir, outDir, user string) (Result, error) {
	timeout, err := time.ParseDuration(spec.Timeout)
	if err != nil {
		return Result{}, fmt.Errorf("%s: timeout: %w", spec.ID, err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostOut := hostOutput(spec, repo, outDir)
	if err := os.MkdirAll(filepath.Dir(hostOut), 0o755); err != nil {
		return Result{}, fmt.Errorf("%s: output dir: %w", spec.ID, err)
	}

	var cmd *exec.Cmd
	var container string
	switch spec.Runtime {
	case "docker":
		container = containerName(spec.ID)
		args, err := dockerArgs(spec, repo, configDir, outDir, user, container)
		if err != nil {
			return Result{}, err
		}
		cmd = exec.CommandContext(ctx, "docker", args...)
		// --rm убирает контейнер при штатном выходе, но убитый CLI (OOM,
		// отмена контекста) оставляет его работать и есть память. Поэтому
		// удаляем по имени всегда.
		defer removeContainer(container)
	case "command":
		if len(spec.Command) == 0 {
			return Result{}, fmt.Errorf("%s: empty command", spec.ID)
		}
		cmd = exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"SGATE_REPO="+repo,
			"SGATE_OUT="+hostOut,
			// SGATE_CONFIG_DIR — каталог analyzers.yaml. Нужен анализаторам,
			// которые живут рядом с конфигом (отдельные модули в этом же
			// репозитории), а сканируют другой репозиторий: `go run` должен
			// запускаться из своего модуля, а не из анализируемого каталога.
			"SGATE_CONFIG_DIR="+configDir,
		)
		for k, v := range spec.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	default:
		return Result{}, fmt.Errorf("%s: unsupported runtime %q", spec.ID, spec.Runtime)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		// Анализатор может вернуть 1/2, если находки есть (Semgrep, Psalm).
		// Это не сбой, если отчёт записан в файл или захвачен stdout.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitAllowed(spec.ExitCodes, exitErr.ExitCode()) {
			if _, statErr := os.Stat(hostOut); statErr == nil || (spec.CaptureStdout && stdout.Len() > 0) {
				err = nil
			}
		}
		if err != nil {
			msg := strings.TrimSpace(stderr.String() + "\n" + stdout.String())
			if len(msg) > 4000 {
				msg = msg[len(msg)-4000:]
			}
			return Result{}, fmt.Errorf("%s: %w: %s", spec.ID, err, msg)
		}
	}
	if spec.CaptureStdout {
		if err := os.WriteFile(hostOut, stdout.Bytes(), 0o644); err != nil {
			return Result{}, fmt.Errorf("%s: write stdout: %w", spec.ID, err)
		}
	}
	if _, err := os.Stat(hostOut); err != nil {
		return Result{}, fmt.Errorf("%s: SARIF not found at %s: %w", spec.ID, hostOut, err)
	}
	output := stderr.String() + "\n" + stdout.String()
	// Нулевой код возврата не гарантирует, что анализ состоялся: часть
	// анализаторов печатает ошибку сборки и отдаёт пустой отчёт. Такие
	// срабатывания считаем сбоем, иначе «0 находок» — ложное отрицание.
	if marker := matchFailOn(spec.FailOn, output); marker != "" {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 1500 {
			msg = msg[len(msg)-1500:]
		}
		return Result{}, fmt.Errorf("%s: анализатор сообщил о сбое (%q), отчёт неполный: %s", spec.ID, marker, msg)
	}
	// Полнота прогона: «0 находок» от анализатора, который не открыл ни одного
	// файла, — не «чисто», а несостоявшийся анализ. Проверяем двумя способами:
	// по прогрессу в логе (gosec: «Checking file: …») и по artifacts в SARIF.
	scanned, err := countScanned(spec, output, hostOut)
	if err != nil {
		return Result{}, err
	}
	return Result{Path: hostOut, ScannedFiles: scanned}, nil
}

// countFromOutput считает просканированные файлы по выводу анализатора.
// total=false — уникальные совпадения (строка прогресса на файл);
// total=true — число из группы (итоговая строка вида «... on 33 files»).
func countFromOutput(re *regexp.Regexp, output string, total bool) int {
	matches := re.FindAllStringSubmatch(output, -1)
	if total {
		best := 0
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(m[1]))
			if err == nil && n > best {
				best = n
			}
		}
		return best
	}
	seen := map[string]struct{}{}
	for _, m := range matches {
		if len(m) > 1 && m[1] != "" {
			seen[m[1]] = struct{}{}
		}
	}
	return len(seen)
}

// countScanned определяет, сколько файлов анализатор реально открыл.
// ScannedRegex приоритетнее: он видит прогресс даже у отчётов, где artifacts
// не заполнены. RequireArtifacts — второй, независимый признак.
func countScanned(spec config.Analyzer, output, reportPath string) (int, error) {
	if spec.ScannedRegex != "" {
		re, err := regexp.Compile(spec.ScannedRegex)
		if err != nil {
			return 0, fmt.Errorf("%s: scanned_regex: %w", spec.ID, err)
		}
		scanned := countFromOutput(re, output, spec.ScannedTotal)
		if scanned < spec.MinScannedFiles {
			return scanned, fmt.Errorf(
				"%s: просканировано %d файлов, ожидалось не меньше %d — анализ не состоялся (отчёт пустой или неполный)",
				spec.ID, scanned, spec.MinScannedFiles)
		}
		return scanned, nil
	}
	if spec.RequireArtifacts {
		n, err := sarif.CountArtifacts(reportPath)
		if err != nil {
			return 0, fmt.Errorf("%s: artifacts: %w", spec.ID, err)
		}
		if n == 0 {
			return 0, fmt.Errorf("%s: отчёт не содержит artifacts — анализатор не открыл ни одного файла, «0 находок» недостоверно", spec.ID)
		}
		return n, nil
	}
	return 0, nil
}

// matchFailOn возвращает первую подстроку из списка, найденную в выводе.
func matchFailOn(patterns []string, output string) string {
	for _, p := range patterns {
		if p != "" && strings.Contains(output, p) {
			return p
		}
	}
	return ""
}

// containerName — уникальное имя контейнера анализатора: позволяет убрать
// его даже если docker CLI убит (OOM/таймаут), не задевая другие прогоны.
func containerName(analyzerID string) string {
	id := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, analyzerID)
	return fmt.Sprintf("sgate-%s-%d-%d", id, os.Getpid(), time.Now().UnixNano())
}

// removeContainer убирает контейнер по имени; ошибки игнорируются: контейнер
// мог уже быть удалён --rm.
func removeContainer(name string) {
	if name == "" {
		return
	}
	rmCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = exec.CommandContext(rmCtx, "docker", "rm", "-f", name).Run()
}

func exitAllowed(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

func hostOutput(spec config.Analyzer, repo, outDir string) string {
	if spec.Runtime == "command" {
		if filepath.IsAbs(spec.Output) {
			return spec.Output
		}
		return filepath.Join(repo, spec.Output)
	}
	return filepath.Join(outDir, strings.TrimPrefix(spec.Output, "/out/"))
}

func dockerArgs(spec config.Analyzer, repo, configDir, outDir, user, container string) ([]string, error) {
	workdir := spec.Workdir
	if workdir == "" {
		workdir = "/src"
	}
	args := []string{
		"run", "--rm",
		"--name", container,
		"--network", spec.Network,
		"--security-opt", "no-new-privileges",
		"--pids-limit", "512",
		"-v", repo + ":/src:ro",
		"-v", outDir + ":/out",
		"-w", workdir,
		"-e", "HOME=/tmp",
	}
	if user != "" {
		args = append(args, "--user", user)
	}
	if spec.Entrypoint != "" {
		args = append(args, "--entrypoint", spec.Entrypoint)
	}
	for k, v := range spec.Env {
		args = append(args, "-e", k+"="+v)
	}
	for _, m := range spec.Mounts {
		src := m.Source
		if !filepath.IsAbs(src) {
			src = filepath.Join(configDir, src)
		}
		abs, err := filepath.Abs(src)
		if err != nil {
			return nil, fmt.Errorf("%s: mount %s: %w", spec.ID, m.Source, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("%s: mount %s: %w", spec.ID, abs, err)
		}
		mount := abs + ":" + m.Target
		if m.ReadOnly {
			mount += ":ro"
		}
		args = append(args, "-v", mount)
	}
	if gitRoot, ok := linkedGitRoot(repo); ok {
		args = append(args, "-v", gitRoot+":"+gitRoot+":ro")
	}
	args = append(args, spec.Image)
	args = append(args, spec.Command...)
	return args, nil
}

// linkedGitRoot возвращает корневой .git для linked worktree, чтобы git
// внутри контейнера видел тот же абсолютный путь, что и .git-файл рабочего дерева.
func linkedGitRoot(repo string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(repo, ".git"))
	if err != nil || !bytes.HasPrefix(raw, []byte("gitdir:")) {
		return "", false
	}
	dir := strings.TrimSpace(strings.TrimPrefix(string(raw), "gitdir:"))
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(repo, dir)
	}
	root := filepath.Clean(dir)
	for {
		if filepath.Base(root) == ".git" {
			return root, true
		}
		parent := filepath.Dir(root)
		if parent == root {
			return "", false
		}
		root = parent
	}
}
