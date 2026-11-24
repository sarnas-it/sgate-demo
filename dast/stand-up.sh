#!/usr/bin/env bash
# Поднимает изолированный стенд Juice Shop на 127.0.0.1:3000.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker compose -f "$root/dast/stand/docker-compose.yml" up -d
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null http://127.0.0.1:3000/; then
    echo "DAST stand: http://127.0.0.1:3000"
    exit 0
  fi
  sleep 1
done
echo "стенд не поднялся за 60 секунд" >&2
exit 1
