package dast

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"code.sarnas.ru/sgate/internal/sarif"
	"gopkg.in/yaml.v3"
)

// Exception — согласованное исключение DAST с владельцем и сроком.
type Exception struct {
	Rule    string `yaml:"rule"`
	Path    string `yaml:"path"`
	Owner   string `yaml:"owner"`
	Expires string `yaml:"expires"` // YYYY-MM-DD
	Reason  string `yaml:"reason"`
}

// Policy — что блокирует релиз, что предупреждает и что можно исключить.
type Policy struct {
	Block      []string    `yaml:"block"`
	Warn       []string    `yaml:"warn"`
	Ignore     []string    `yaml:"ignore"`
	Exceptions []Exception `yaml:"exceptions"`
}

func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dast policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse dast policy: %w", err)
	}
	if len(p.Block) == 0 {
		p.Block = []string{"critical", "high"}
	}
	if len(p.Warn) == 0 {
		p.Warn = []string{"medium"}
	}
	for i, ex := range p.Exceptions {
		if ex.Owner == "" || ex.Expires == "" {
			return nil, fmt.Errorf("exception #%d: owner and expires are required", i+1)
		}
		if _, err := time.Parse("2006-01-02", ex.Expires); err != nil {
			return nil, fmt.Errorf("exception #%d: expires: %w", i+1, err)
		}
		if ex.Rule == "" && ex.Path == "" {
			return nil, fmt.Errorf("exception #%d: rule or path is required", i+1)
		}
	}
	return &p, nil
}

// Evaluate делит находки на блокирующие и предупреждения с учётом исключений.
func (p *Policy) Evaluate(findings []sarif.Finding) (blocking, warnings []sarif.Finding, excepted int) {
	blockSet := toSet(p.Block)
	warnSet := toSet(p.Warn)
	now := time.Now()
	for _, f := range findings {
		if p.excepted(f, now) {
			excepted++
			continue
		}
		sev := strings.ToLower(f.Severity)
		switch {
		case blockSet[sev]:
			blocking = append(blocking, f)
		case warnSet[sev]:
			warnings = append(warnings, f)
		}
	}
	return blocking, warnings, excepted
}

func toSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[strings.ToLower(s)] = true
	}
	return out
}

func (p *Policy) excepted(f sarif.Finding, now time.Time) bool {
	for _, ex := range p.Exceptions {
		expires, err := time.Parse("2006-01-02", ex.Expires)
		if err != nil || now.After(expires.Add(24*time.Hour)) {
			continue
		}
		if ex.Rule != "" && !strings.EqualFold(ex.Rule, f.RuleID) {
			continue
		}
		if ex.Path != "" && !pathMatches(f.File, ex.Path) {
			continue
		}
		return true
	}
	return false
}

func pathMatches(raw, prefix string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.HasPrefix(raw, prefix)
	}
	return strings.HasPrefix(u.Path, prefix)
}
