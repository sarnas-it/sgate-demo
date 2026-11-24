// Package dast: scope, discovery целей и общие правила активных проверок.
package dast

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope — согласованный периметр DAST. Всё, что вне scope, не сканируется.
type Scope struct {
	Target       string   `yaml:"target"`
	AllowedHosts []string `yaml:"allowed_hosts"`
	MaxRPS       int      `yaml:"max_rps"`
	Exclusions   []string `yaml:"exclusions"`
}

// Load читает scope и проверяет, что target — http(s) URL.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	var s Scope
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse scope: %w", err)
	}
	u, err := url.Parse(s.Target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("scope.target must be http(s) URL")
	}
	if len(s.AllowedHosts) == 0 {
		s.AllowedHosts = []string{u.Hostname()}
	}
	if s.MaxRPS <= 0 {
		s.MaxRPS = 5
	}
	return &s, nil
}

// Allowed проверяет URL по схеме, хосту и исключениям.
func (s *Scope) Allowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	host := u.Hostname()
	okHost := false
	for _, h := range s.AllowedHosts {
		if strings.EqualFold(host, h) {
			okHost = true
			break
		}
	}
	if !okHost {
		return false
	}
	for _, ex := range s.Exclusions {
		if strings.HasPrefix(u.Path, ex) {
			return false
		}
	}
	return true
}
