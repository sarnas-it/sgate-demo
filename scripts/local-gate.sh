#!/usr/bin/env bash
# Единый гейт: Guardrail (секреты/ПДн) + Deps (SCA).
# Контракт: код 1, если хотя бы один слой нашёл блокирующую находку.
#
# Использование:
#   DEPS_BIN=... GUARDRAIL_BIN=... scripts/local-gate.sh [base] [head]
#
# По умолчанию: base=origin/main, head=HEAD.

set -euo pipefail

BASE="${1:-origin/main}"
HEAD="${2:-HEAD}"
DEPS_BIN="${DEPS_BIN:-deps}"
GUARDRAIL_BIN="${GUARDRAIL_BIN:-guardrail}"
BLOCK_SEVERITIES="${BLOCK_SEVERITIES:-CRITICAL,HIGH}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failed=0
summary=()

echo "== Guardrail: секреты и ПДн ($BASE..$HEAD)"
if "$GUARDRAIL_BIN" scan \
      --repo . \
      --base "$BASE" \
      --head "$HEAD" \
      --config guardrail.yml \
      --json "$tmp/guardrail.json" \
      --sarif "$tmp/guardrail.sarif"; then
  summary+=("Guardrail: чисто")
else
  failed=1
  summary+=("Guardrail: БЛОКИРОВКА")
fi

echo
echo "== Deps: уязвимые зависимости ($BASE..$HEAD)"
if "$DEPS_BIN" scan \
      --repo . \
      --base "$BASE" \
      --head "$HEAD" \
      --json "$tmp/deps.json" \
      --markdown; then
  counts="$(python3 - "$tmp/deps.json" "$BLOCK_SEVERITIES" <<'PY'
import json
import sys

path, block = sys.argv[1], set(sys.argv[2].split(","))
report = json.load(open(path))
counts = {}
for package in report.get("vulnerable", []):
    for advisory in package.get("advisories", []):
        severity = advisory.get("severity", "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1

blocking = sum(counts.get(severity, 0) for severity in block)
print(blocking)
print(", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "находок нет")
PY
)"
  blocking="$(echo "$counts" | sed -n '1p')"
  detail="$(echo "$counts" | sed -n '2p')"
  if [ "$blocking" -gt 0 ]; then
    failed=1
    summary+=("Deps: БЛОКИРОВКА ($blocking в $BLOCK_SEVERITIES; $detail)")
  else
    summary+=("Deps: чисто ($detail)")
  fi
else
  failed=1
  summary+=("Deps: ошибка запуска")
fi

echo
echo "== Итог"
for line in "${summary[@]}"; do
  echo " - $line"
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "Гейт не пройден: релиз блокирован."
  exit 1
fi

echo
echo "Гейт пройден."
