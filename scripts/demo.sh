#!/usr/bin/env bash
# Самопроверяющееся демо Security Gate.
#
# Показывает, что сервис работает без выхода в сеть:
#   1. секрет в PR   → Guardrail останавливает пайп;
#   2. ПДн в PR      → Guardrail останавливает пайп;
#   3. CRITICAL-зависимость → Deps останавливает пайп;
#   4. исправление   → гейт проходит;
#   5. чистый дифф   → гейт проходит.
#
# Каждый сценарий запускается в Docker с --network none. Сеть нужна только
# один раз — скачать образ alpine/git и собрать бинарники.
#
# Код возврата 0 — все сценарии повели себя как ожидалось, 1 — нет.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

tools="${TOOLS_DIR:-$root/.tools}"
image="${DEMO_IMAGE:-alpine/git:latest}"
out="$root/.demo-out"
base="${BASE_REF:-main}"

if [ ! -x "$tools/deps" ] || [ ! -x "$tools/guardrail" ]; then
  echo "Нет бинарников в $tools — собираю."
  "$root/scripts/build-tools.sh"
fi

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "Скачиваю образ $image (единственный сетевой шаг)."
  docker pull "$image" >/dev/null
fi

rm -rf "$out"
mkdir -p "$out"

pubkey="$(cat fixtures/osv-dataset/pubkey.hex)"
docker_user="$(id -u):$(id -g)"

results=()
failures=0

run_guardrail() {
  local base_ref="$1" head_ref="$2" log="$3"
  docker run --rm --network none \
    --user "$docker_user" \
    --entrypoint /usr/local/bin/guardrail \
    -v "$root:/repo" \
    -v "$tools/guardrail:/usr/local/bin/guardrail:ro" \
    -w /repo "$image" \
    scan --repo . --base "$base_ref" --head "$head_ref" --config guardrail.yml \
    >"$log" 2>&1
}

run_deps() {
  local base_ref="$1" head_ref="$2" json="$3" log="$4"
  docker run --rm --network none \
    --user "$docker_user" \
    --entrypoint /usr/local/bin/deps \
    -v "$root:/repo" \
    -v "$root/fixtures/osv-dataset:/dataset:ro" \
    -v "$out:/out" \
    -v "$tools/deps:/usr/local/bin/deps:ro" \
    -w /repo "$image" \
    scan --repo . --base "$base_ref" --head "$head_ref" \
    --dataset /dataset --pubkey-hex "$pubkey" --max-age 87600h \
    --min-severity HIGH --json "/out/$(basename "$json")" \
    >"$log" 2>&1
}

expect_block_secrets() {
  local title="$1" head_ref="$2" log="$out/$3"
  if run_guardrail "$base" "$head_ref" "$log"; then
    results+=("FAIL | $title | Guardrail пропустил")
    failures=$((failures + 1))
  else
    results+=("ok   | $title | Guardrail остановил пайп")
  fi
}

expect_pass_secrets() {
  local title="$1" head_ref="$2" log="$out/$3"
  if run_guardrail "$base" "$head_ref" "$log"; then
    results+=("ok   | $title | Guardrail пропустил")
  else
    results+=("FAIL | $title | Guardrail заблокировал чистый дифф")
    failures=$((failures + 1))
  fi
}

expect_sca() {
  local title="$1" head_ref="$2" want="$3" json="$out/$4" log="$out/$5"
  : >"$json"
  run_deps "$base" "$head_ref" "$json" "$log" || true
  if python3 "$root/scripts/policy.py" "$json" >>"$log" 2>&1; then
    got="pass"
  else
    got="block"
  fi
  if [ "$got" = "$want" ]; then
    results+=("ok   | $title | Deps: $got")
  else
    results+=("FAIL | $title | Deps: ожидали $want, получили $got")
    failures=$((failures + 1))
  fi
}

echo "== 1/5 Секрет в PR"
expect_block_secrets "Секрет в PR" "demo/secret-leak" "secret.log"

echo "== 2/5 ПДн в PR"
expect_block_secrets "ПДн в PR" "demo/pii-leak" "pii.log"

echo "== 3/5 CRITICAL-зависимость"
expect_sca "CRITICAL-зависимость" "demo/critical-dependency" "block" "sca-critical.json" "sca-critical.log"

echo "== 4/5 Исправление зависимости"
expect_sca "Исправление next" "demo/fix-next" "pass" "sca-fix.json" "sca-fix.log"

echo "== 5/5 Чистый дифф"
expect_pass_secrets "Чистый дифф" "demo/fix-next" "clean.log"

echo
echo "=== Результаты"
printf '%s\n' "${results[@]}"
echo
echo "Логи: $out"
if [ "$failures" -ne 0 ]; then
  echo "Демо не прошло: $failures сценариев из ${#results[@]}."
  exit 1
fi
echo "Все ${#results[@]} сценариев отработали как ожидалось."
