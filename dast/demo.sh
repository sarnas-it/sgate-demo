#!/usr/bin/env bash
# Короткое демо DAST: стенд → discovery → ZAP baseline → отчёт.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
trap '$root/dast/stand-down.sh >/dev/null 2>&1 || true' EXIT

"$root/dast/stand-up.sh"
cd "$root/core"
go run ./cmd/sgatedast discover \
  -scope ../dast/scope.example.yaml \
  -out ../dast/out/urls.txt
DAST_CONFIRM=1 go run ./cmd/sgatedast scan \
  -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml \
  -id zap-baseline -policy ../dast/policy.yaml -out ../dast/out
echo "демо готово: $root/dast/out/report.md"
