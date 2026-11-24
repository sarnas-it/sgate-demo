package dast

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Scanner — сменный DAST-сканер. Как и SAST-адаптер, SGATE не знает его
// внутренностей: запускает контейнер и читает отчёт.
type Scanner struct {
	ID         string   `yaml:"id"`
	Image      string   `yaml:"image"`
	Entrypoint string   `yaml:"entrypoint"`
	Workdir    string   `yaml:"workdir"`
	Command    []string `yaml:"command"`
	Output     string   `yaml:"output"`
	Format     string   `yaml:"format"`
	Network    string   `yaml:"network"`
	Timeout    string   `yaml:"timeout"`
	ExitCodes  []int    `yaml:"exit_codes"`
}

type ScannerConfig struct {
	Scanners []Scanner `yaml:"scanners"`
}

func LoadScanners(path string) (*ScannerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scanners: %w", err)
	}
	var c ScannerConfig
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse scanners: %w", err)
	}
	if len(c.Scanners) == 0 {
		return nil, fmt.Errorf("no scanners in %s", path)
	}
	seen := map[string]bool{}
	for i := range c.Scanners {
		s := &c.Scanners[i]
		if s.ID == "" || s.Image == "" || len(s.Command) == 0 || s.Output == "" {
			return nil, fmt.Errorf("scanner #%d: id, image, command, output are required", i+1)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("duplicate scanner id %q", s.ID)
		}
		seen[s.ID] = true
		if s.Format == "" {
			s.Format = "zap-json"
		}
		if s.Workdir == "" {
			s.Workdir = "/out"
		}
		if s.Network == "" {
			s.Network = "host"
		}
		if s.Timeout == "" {
			s.Timeout = "10m"
		}
		if len(s.ExitCodes) == 0 {
			s.ExitCodes = []int{0, 1}
		}
		if _, err := time.ParseDuration(s.Timeout); err != nil {
			return nil, fmt.Errorf("%s: timeout: %w", s.ID, err)
		}
	}
	return &c, nil
}

// Run выполняет сканер по target и возвращает путь к отчёту на хосте.
func (s Scanner) Run(ctx context.Context, target, outDir, user string) (string, error) {
	timeout, err := time.ParseDuration(s.Timeout)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"run", "--rm",
		"--network", s.Network,
		"--security-opt", "no-new-privileges",
		"--pids-limit", "512",
		"-v", outDir + ":" + s.Workdir,
		"-w", s.Workdir,
	}
	if user != "" {
		args = append(args, "--user", user)
	}
	if s.Entrypoint != "" {
		args = append(args, "--entrypoint", s.Entrypoint)
	}
	args = append(args, s.Image)
	for _, a := range s.Command {
		args = append(args, strings.ReplaceAll(a, "{{target}}", target))
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !(exitErr != nil && exitAllowed(s.ExitCodes, exitErr.ExitCode())) {
			return "", fmt.Errorf("%s: %w: %s", s.ID, err, strings.TrimSpace(stderr.String()))
		}
	}
	hostOut := filepath.Join(outDir, strings.TrimPrefix(s.Output, s.Workdir+"/"))
	if _, err := os.Stat(hostOut); err != nil {
		return "", fmt.Errorf("%s: report not found at %s: %w", s.ID, hostOut, err)
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
