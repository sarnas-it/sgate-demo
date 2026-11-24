package dast

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"code.sarnas.ru/sgate/internal/sarif"
)

// AppendFindings дописывает нормализованные находки в общий JSONL.
func AppendFindings(path string, findings []sarif.Finding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, finding := range findings {
		if err := enc.Encode(finding); err != nil {
			return err
		}
	}
	return nil
}

// ReadFindings читает общий JSONL находок.
func ReadFindings(path string) ([]sarif.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	defer f.Close()
	var out []sarif.Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var finding sarif.Finding
		if err := json.Unmarshal(sc.Bytes(), &finding); err != nil {
			return nil, fmt.Errorf("parse findings: %w", err)
		}
		out = append(out, finding)
	}
	return out, sc.Err()
}
