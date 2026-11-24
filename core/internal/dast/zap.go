package dast

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"

	"code.sarnas.ru/sgate/internal/sarif"
)

type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID  string `json:"pluginid"`
			Alert     string `json:"alert"`
			RiskCode  string `json:"riskcode"`
			Desc      string `json:"desc"`
			Instances []struct {
				URI    string `json:"uri"`
				Method string `json:"method"`
				Param  string `json:"param"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// ParseZAPJSON нормализует ZAP JSON (-J) в общую модель SGATE.
func ParseZAPJSON(path, analyzerID string) ([]sarif.Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read zap json: %w", err)
	}
	var r zapReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse zap json: %w", err)
	}
	var out []sarif.Finding
	for _, site := range r.Site {
		for _, alert := range site.Alerts {
			instances := alert.Instances
			if len(instances) == 0 {
				instances = []struct {
					URI    string `json:"uri"`
					Method string `json:"method"`
					Param  string `json:"param"`
				}{{URI: site.Name}}
			}
			for _, inst := range instances {
				f := sarif.Finding{
					Analyzer: analyzerID,
					RuleID:   alert.PluginID,
					Severity: severityFromZAP(alert.RiskCode),
					Message:  cleanMessage(alert.Alert + ": " + alert.Desc),
					File:     inst.URI,
					Line:     1,
				}
				sum := sha1.Sum([]byte(analyzerID + "|" + alert.PluginID + "|" + inst.URI + "|" + inst.Param))
				f.Fingerprint = hex.EncodeToString(sum[:])
				out = append(out, f)
			}
		}
	}
	return out, nil
}

var tagRE = regexp.MustCompile(`<[^>]+>`)

func cleanMessage(s string) string {
	s = html.UnescapeString(tagRE.ReplaceAllString(s, " "))
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > 500 {
		s = string([]rune(s)[:500]) + "…"
	}
	return s
}

func severityFromZAP(code string) string {
	switch code {
	case "3":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	default:
		return "info"
	}
}
