package dast

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"code.sarnas.ru/sgate/internal/sarif"
)

// PassiveScan проверяет только публичные заголовки, cookies и служебные файлы.
// Никаких атакующих payload'ов и обхода авторизации.
func PassiveScan(ctx context.Context, client *http.Client, scope *Scope) ([]sarif.Finding, error) {
	if !scope.Allowed(scope.Target) {
		return nil, fmt.Errorf("target вне scope: %s", scope.Target)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scope.Target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	var out []sarif.Finding
	add := func(rule, sev, msg string) {
		f := sarif.Finding{Analyzer: "passive-wstg", RuleID: rule, Severity: sev, Message: msg, File: scope.Target, Line: 1}
		sum := sha1.Sum([]byte(rule + "|" + scope.Target + "|" + msg))
		f.Fingerprint = hex.EncodeToString(sum[:])
		out = append(out, f)
	}

	if resp.Header.Get("Content-Security-Policy") == "" {
		add("passive-csp", "medium", "не задан Content-Security-Policy")
	}
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors") {
		add("passive-xfo", "medium", "не задан X-Frame-Options и нет CSP frame-ancestors")
	}
	if !strings.EqualFold(resp.Header.Get("X-Content-Type-Options"), "nosniff") {
		add("passive-nosniff", "low", "нет X-Content-Type-Options: nosniff")
	}
	if resp.Header.Get("Referrer-Policy") == "" {
		add("passive-referrer", "low", "не задан Referrer-Policy")
	}
	if resp.Header.Get("Permissions-Policy") == "" {
		add("passive-permissions", "low", "не задан Permissions-Policy")
	}
	if u, _ := url.Parse(scope.Target); u != nil && u.Scheme == "https" && resp.Header.Get("Strict-Transport-Security") == "" {
		add("passive-hsts", "medium", "нет Strict-Transport-Security при HTTPS")
	}
	if v := resp.Header.Get("Server"); v != "" {
		add("passive-server", "info", "раскрыт Server: "+v)
	}
	if v := resp.Header.Get("X-Powered-By"); v != "" {
		add("passive-powered", "low", "раскрыт X-Powered-By: "+v)
	}
	for _, c := range resp.Cookies() {
		if !c.Secure {
			add("passive-cookie-secure", "medium", "cookie без Secure: "+c.Name)
		}
		if !c.HttpOnly {
			add("passive-cookie-httponly", "low", "cookie без HttpOnly: "+c.Name)
		}
	}

	checks := []struct {
		path, rule, sev, marker, msg string
	}{
		{"/.env", "passive-env", "critical", "=", "открыт .env с переменными окружения"},
		{"/.git/HEAD", "passive-git", "high", "ref:", "открыт .git/HEAD"},
		{"/phpinfo.php", "passive-phpinfo", "medium", "PHP Version", "открыт phpinfo()"},
		{"/server-status", "passive-server-status", "medium", "Apache Server Status", "открыт server-status"},
	}
	for _, c := range checks {
		u := strings.TrimRight(scope.Target, "/") + c.path
		if !scope.Allowed(u) {
			continue
		}
		body, status, err := getBody(ctx, client, u)
		if err != nil || status != http.StatusOK || !strings.Contains(body, c.marker) {
			continue
		}
		if c.rule == "passive-env" && !looksLikeEnv(body) {
			continue // SPA отдаёт HTML на любой путь
		}
		add(c.rule, c.sev, c.msg+": "+u)
	}
	return out, nil
}

var envLine = regexp.MustCompile(`(?m)^[A-Za-z_][A-Za-z0-9_]*=`)

func looksLikeEnv(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return false
	}
	return len(envLine.FindAllString(body, 3)) >= 2
}

func getBody(ctx context.Context, client *http.Client, raw string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), resp.StatusCode, err
}
