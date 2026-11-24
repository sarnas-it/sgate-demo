#!/usr/bin/env bash
# ZAP baseline по локальному стенду. Только 127.0.0.1/localhost.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${DAST_TARGET:-http://127.0.0.1:3000}"
out="$root/dast/out"

if [ "${DAST_CONFIRM:-}" != "1" ]; then
  echo "Перед запуском: DAST_CONFIRM=1 (подтверждение согласованного стенда)" >&2
  exit 1
fi
case "$target" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "разрешён только локальный стенд, получено: $target" >&2; exit 1 ;;
esac

mkdir -p "$out"
docker run --rm --network host \
  -v "$out:/zap/wrk:rw" \
  zaproxy/zap-stable:latest \
  zap-baseline.py -t "$target" \
    -J report.json -w report.md -r report.html

echo "отчёты: $out"
