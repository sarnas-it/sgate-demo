// Package config загружает описание анализаторов SGATE.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Mount — дополнительный каталог, который монтируется в контейнер анализатора.
type Mount struct {
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only"`
}

// Analyzer — сменный SAST-анализатор. SGATE не знает его внутренностей:
// запускает команду/образ и читает SARIF.
type Analyzer struct {
	ID        string            `yaml:"id"`
	Languages []string          `yaml:"languages"`
	Runtime   string            `yaml:"runtime"` // docker | command
	Image     string            `yaml:"image"`
	Command   []string          `yaml:"command"`
	Workdir   string            `yaml:"workdir"`
	Mounts    []Mount           `yaml:"mounts"`
	Output    string            `yaml:"output"`
	Network   string            `yaml:"network"`
	Timeout   string            `yaml:"timeout"`
	Env       map[string]string `yaml:"env"`
	// Requires — файлы/каталоги, без которых анализатор не имеет смысла
	// (например, go.mod для gosec). Проверяются относительно корня репозитория.
	Requires []string `yaml:"requires"`
	// Format — формат вывода: sarif (по умолчанию) или bandit-json.
	Format string `yaml:"format"`
}

// Config — корневой файл analyzers.yaml.
type Config struct {
	Version   int        `yaml:"version"`
	Analyzers []Analyzer `yaml:"analyzers"`
	// Exclude — пути, которые не считаются находками (fixtures, testdata).
	Exclude []string `yaml:"exclude"`
}

// Load читает и валидирует конфиг.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("unsupported config version %d", c.Version)
	}
	if len(c.Analyzers) == 0 {
		return nil, fmt.Errorf("no analyzers in %s", path)
	}
	seen := map[string]bool{}
	for i := range c.Analyzers {
		a := &c.Analyzers[i]
		if a.ID == "" {
			return nil, fmt.Errorf("analyzer #%d: id is required", i+1)
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("duplicate analyzer id %q", a.ID)
		}
		seen[a.ID] = true
		if len(a.Languages) == 0 {
			return nil, fmt.Errorf("%s: languages is required", a.ID)
		}
		if a.Runtime == "" {
			a.Runtime = "docker"
		}
		if a.Runtime != "docker" && a.Runtime != "command" {
			return nil, fmt.Errorf("%s: runtime must be docker or command", a.ID)
		}
		if a.Runtime == "docker" && a.Image == "" {
			return nil, fmt.Errorf("%s: image is required for docker runtime", a.ID)
		}
		if len(a.Command) == 0 {
			return nil, fmt.Errorf("%s: command is required", a.ID)
		}
		if a.Output == "" {
			return nil, fmt.Errorf("%s: output is required", a.ID)
		}
		if a.Timeout == "" {
			a.Timeout = "10m"
		}
		if _, err := time.ParseDuration(a.Timeout); err != nil {
			return nil, fmt.Errorf("%s: timeout: %w", a.ID, err)
		}
		if a.Network == "" {
			a.Network = "none"
		}
		if a.Format == "" {
			a.Format = "sarif"
		}
		switch a.Format {
		case "sarif", "bandit-json":
		default:
			return nil, fmt.Errorf("%s: unsupported format %q", a.ID, a.Format)
		}
	}
	return &c, nil
}
