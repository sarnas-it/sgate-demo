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
	Auth         *Auth    `yaml:"auth"`
}

// Auth хранит только имена env-переменных, не сами секреты.
type Auth struct {
	Mode             string `yaml:"mode"` // none | bearer | header | cookie
	Header           string `yaml:"header"`
	TokenEnv         string `yaml:"token_env"`
	CookieEnv        string `yaml:"cookie_env"`
	TestAccountsOnly bool   `yaml:"test_accounts_only"`
}

// AuthHeader собирает заголовок из env. Секрет не попадает в ошибки.
func (s *Scope) AuthHeader() (string, error) {
	if s.Auth == nil || s.Auth.Mode == "" || s.Auth.Mode == "none" {
		return "", nil
	}
	switch s.Auth.Mode {
	case "bearer":
		token := os.Getenv(s.Auth.TokenEnv)
		if s.Auth.TokenEnv == "" || token == "" {
			return "", fmt.Errorf("auth: env %s is empty", s.Auth.TokenEnv)
		}
		return "Authorization: Bearer " + token, nil
	case "header":
		header := s.Auth.Header
		if header == "" {
			header = "Authorization"
		}
		token := os.Getenv(s.Auth.TokenEnv)
		if s.Auth.TokenEnv == "" || token == "" {
			return "", fmt.Errorf("auth: env %s is empty", s.Auth.TokenEnv)
		}
		return header + ": " + token, nil
	case "cookie":
		value := os.Getenv(s.Auth.CookieEnv)
		if s.Auth.CookieEnv == "" || value == "" {
			return "", fmt.Errorf("auth: env %s is empty", s.Auth.CookieEnv)
		}
		return "Cookie: " + value, nil
	default:
		return "", fmt.Errorf("auth: unsupported mode %q", s.Auth.Mode)
	}
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
