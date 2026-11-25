package rules

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree создаёт временный репозиторий из карты «путь → исходник».
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func rulesOf(fs []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Rule]++
	}
	return out
}

func TestBrokerEntityWithoutSubject(t *testing.T) {
	root := writeTree(t, map[string]string{
		"consumer/handler.go": `package consumer

import (
	"encoding/json"

	"github.com/ThreeDotsLabs/watermill/message"
)

type envelope struct {
	Entity   string ` + "`json:\"entity\"`" + `
	ClientID string ` + "`json:\"client_id\"`" + `
}

func (c *Consumer) handleData(msg *message.Message) error {
	var m envelope
	if err := json.Unmarshal(msg.Payload, &m); err != nil {
		return err
	}
	c.write(m.Entity)
	return nil
}
`,
	})

	findings, scanned, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 1 {
		t.Fatalf("scanned = %v", scanned)
	}
	got := rulesOf(findings)
	if got["sgate-ast-broker-entity-subject"] != 1 {
		t.Fatalf("ожидалась 1 находка broker-entity, получено %v (%+v)", got, findings)
	}
}

func TestBrokerEntityWithSubjectChecked(t *testing.T) {
	root := writeTree(t, map[string]string{
		"consumer/handler.go": `package consumer

import (
	"encoding/json"
	"strings"

	"github.com/ThreeDotsLabs/watermill/message"
)

type envelope struct {
	Entity string ` + "`json:\"entity\"`" + `
}

func (c *Consumer) handleData(msg *message.Message) error {
	var m envelope
	if err := json.Unmarshal(msg.Payload, &m); err != nil {
		return err
	}
	if m.Entity != strings.TrimPrefix(msg.Subject, "etl.") {
		return nil
	}
	c.write(m.Entity)
	return nil
}
`,
	})

	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-ast-broker-entity-subject"]; n != 0 {
		t.Fatalf("сверка с subject есть, находок быть не должно: %+v", findings)
	}
}

func TestBrokerEntityIgnoresNonMessageParam(t *testing.T) {
	root := writeTree(t, map[string]string{
		"internal/model.go": `package internal

import "encoding/json"

type payload struct {
	Entity string ` + "`json:\"entity\"`" + `
}

func decode(raw []byte) payload {
	var p payload
	_ = json.Unmarshal(raw, &p)
	_ = p.Entity
	return p
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-ast-broker-entity-subject"]; n != 0 {
		t.Fatalf("не брокерский обработчик — находок быть не должно: %+v", findings)
	}
}

func TestIdentityParamFromMap(t *testing.T) {
	root := writeTree(t, map[string]string{
		"internal/datasource/rls.go": `package datasource

var contextParams = map[string]string{
	"subject_org": "app.subject_org",
	"snapshot_id": "app.snapshot_id",
}

func org(params map[string]any) any {
	return params["subject_org"]
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	// 3 вхождения: два ключа словаря и одно чтение params["subject_org"].
	if n := rulesOf(findings)["sgate-ast-identity-param"]; n != 3 {
		t.Fatalf("ожидалось 3 находки identity-param, получено %d: %+v", n, findings)
	}
}

func TestIdentityParamAbsent(t *testing.T) {
	root := writeTree(t, map[string]string{
		"internal/ok.go": `package internal

func org(params map[string]any) any {
	return params["org_id"]
}
`,
	})
	findings, _, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := rulesOf(findings)["sgate-ast-identity-param"]; n != 0 {
		t.Fatalf("org_id — не identity-параметр: %+v", findings)
	}
}

func TestSkipsVendorTestsAndHiddenDirs(t *testing.T) {
	root := writeTree(t, map[string]string{
		"vendor/dep/x.go":       "package dep\n\nvar _ = params[\"subject_org\"]\n",
		"testdata/case.go":      "package testdata\n\nvar _ = params[\"subject_org\"]\n",
		"internal/real.go":      "package internal\n\nvar _ = params[\"subject_org\"]\n",
		"internal/real_test.go": "package internal\n\nvar _ = params[\"subject_org\"]\n",
	})
	findings, scanned, err := Analyze(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 1 || scanned[0] != "internal/real.go" {
		t.Fatalf("scanned = %v, want [internal/real.go]", scanned)
	}
	if n := rulesOf(findings)["sgate-ast-identity-param"]; n != 1 {
		t.Fatalf("ожидалась 1 находка в internal/real.go, получено %d", n)
	}
}
