#!/usr/bin/env bash
# Собирает статические бинарники Deps и Guardrail для демо.
# Пути к исходникам можно переопределить: DEPS_SRC, GUARDRAIL_SRC.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tools="${TOOLS_DIR:-$root/.tools}"
deps_src="${DEPS_SRC:-$HOME/GolandProjects/repo-review-research/deps}"
guardrail_src="${GUARDRAIL_SRC:-$HOME/GolandProjects/guardrail}"

mkdir -p "$tools"

echo "== deps: $deps_src"
(cd "$deps_src" && CGO_ENABLED=0 go build -o "$tools/deps" ./cmd/deps)

echo "== guardrail: $guardrail_src"
(cd "$guardrail_src" && CGO_ENABLED=0 go build -o "$tools/guardrail" ./cmd/guardrail)

file "$tools/deps" "$tools/guardrail"
