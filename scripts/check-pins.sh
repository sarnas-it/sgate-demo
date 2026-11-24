#!/usr/bin/env bash
# Все образы в конфигах SGATE должны быть закреплены по digest.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
while IFS= read -r line; do
  case "$line" in
    *'@sha256:'*) ;;
    *) echo "not pinned: $line" >&2; fail=1 ;;
  esac
done < <(grep -HnE '^[[:space:]]*image:' \
  "$root/core/analyzers.yaml" \
  "$root/dast/scanners.yaml" \
  "$root/dast/stand/docker-compose.yml")
if [ "$fail" -ne 0 ]; then
  echo "закрепите образы как image@sha256:..." >&2
  exit 1
fi
echo "all images pinned"
