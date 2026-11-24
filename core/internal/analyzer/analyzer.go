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
	"strings"
	"time"

	"code.sarnas.ru/sgate/internal/config"
)

// Run запускает анализатор и возвращает путь к SARIF-файлу на хосте.
func Run(ctx context.Context, spec config.Analyzer, repo, configDir, outDir, user string) (string, error) {
	timeout, err := time.ParseDuration(spec.Timeout)
	if err != nil {
		return "", fmt.Errorf("%s: timeout: %w", spec.ID, err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostOut := hostOutput(spec, repo, outDir)
	if err := os.MkdirAll(filepath.Dir(hostOut), 0o755); err != nil {
		return "", fmt.Errorf("%s: output dir: %w", spec.ID, err)
	}

	var cmd *exec.Cmd
	switch spec.Runtime {
	case "docker":
		args, err := dockerArgs(spec, repo, configDir, outDir, user)
		if err != nil {
			return "", err
		}
		cmd = exec.CommandContext(ctx, "docker", args...)
	case "command":
		if len(spec.Command) == 0 {
			return "", fmt.Errorf("%s: empty command", spec.ID)
		}
		cmd = exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"SGATE_REPO="+repo,
			"SGATE_OUT="+hostOut,
		)
		for k, v := range spec.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	default:
		return "", fmt.Errorf("%s: unsupported runtime %q", spec.ID, spec.Runtime)
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
			return "", fmt.Errorf("%s: %w: %s", spec.ID, err, msg)
		}
	}
	if spec.CaptureStdout {
		if err := os.WriteFile(hostOut, stdout.Bytes(), 0o644); err != nil {
			return "", fmt.Errorf("%s: write stdout: %w", spec.ID, err)
		}
	}
	if _, err := os.Stat(hostOut); err != nil {
		return "", fmt.Errorf("%s: SARIF not found at %s: %w", spec.ID, hostOut, err)
	}
	return hostOut, nil
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

func dockerArgs(spec config.Analyzer, repo, configDir, outDir, user string) ([]string, error) {
	workdir := spec.Workdir
	if workdir == "" {
		workdir = "/src"
	}
	args := []string{
		"run", "--rm",
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
