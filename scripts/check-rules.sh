#!/usr/bin/env bash
# Проверка правил SAST на фикстурах с аннотациями.
#
# Каждая строка фикстуры помечена ожиданием:
#   // ruleid: <rule-id>  — правило обязано сработать на этой строке;
#   // ok: <rule-id>      — правило обязано молчать на этой строке.
#
# Скрипт прогоняет semgrep по sast-rules/ и сверяет реальные находки с
# аннотациями. Нужен, чтобы правило не регрессировало: слишком широкое
# начинает шуметь на защищённом коде, слишком узкое — перестаёт ловить.
#
# Использование:
#   scripts/check-rules.sh            # образ из core/analyzers.yaml
#   SEMGREP_IMAGE=... scripts/check-rules.sh
#
# Код возврата 0 — все ожидания совпали, 1 — есть расхождения.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Образ берём из конфига анализаторов, чтобы проверка правил шла тем же
# semgrep, что и боевой прогон (закреплён по digest).
if [ -z "${SEMGREP_IMAGE:-}" ]; then
  SEMGREP_IMAGE="$(awk '/^[[:space:]]*image: semgrep\//{sub(/^[[:space:]]*image:[[:space:]]*/, ""); print; exit}' core/analyzers.yaml)"
fi
if [ -z "$SEMGREP_IMAGE" ]; then
  echo "не удалось определить образ semgrep (SEMGREP_IMAGE или core/analyzers.yaml)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== Правила SAST на фикстурах ($SEMGREP_IMAGE)"
docker run --rm --network none \
  -v "$root/sast-rules:/rules:ro" \
  -v "$root/fixtures/sast-rules:/fixtures:ro" \
  -w /fixtures \
  "$SEMGREP_IMAGE" \
  semgrep scan --config /rules --json --metrics=off --quiet \
  --output /tmp/semgrep.json /fixtures >/dev/null 2>"$tmp/semgrep.err" || true

if [ ! -s "$tmp/semgrep.json" ]; then
  # --output пишется внутрь контейнера; забираем через stdout-вариант.
  docker run --rm --network none \
    -v "$root/sast-rules:/rules:ro" \
    -v "$root/fixtures/sast-rules:/fixtures:ro" \
    -w /fixtures \
    "$SEMGREP_IMAGE" \
    semgrep scan --config /rules --json --metrics=off --quiet /fixtures \
    >"$tmp/semgrep.json" 2>"$tmp/semgrep.err" || true
fi

if [ ! -s "$tmp/semgrep.json" ]; then
  echo "semgrep не вернул JSON:" >&2
  cat "$tmp/semgrep.err" >&2
  exit 2
fi

python3 - "$tmp/semgrep.json" "$root/fixtures/sast-rules" <<'PY'
import json
import pathlib
import re
import sys

report_path, fixtures_root = sys.argv[1], pathlib.Path(sys.argv[2])
report = json.load(open(report_path))

# Аннотации: "ruleid: <id>" и "ok: <id>" в комментарии на строке.
annotation_re = re.compile(r"//\s*(ruleid|ok):\s*([a-z0-9-]+)")

expected_hit = {}   # (file, line) -> rule
expected_clean = {}  # (file, line) -> rule
for path in sorted(fixtures_root.rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(fixtures_root)
    for lineno, text in enumerate(path.read_text().splitlines(), start=1):
        m = annotation_re.search(text)
        if not m:
            continue
        kind, rule = m.group(1), m.group(2)
        key = (str(rel), lineno)
        if kind == "ruleid":
            expected_hit[key] = rule
        else:
            expected_clean[key] = rule

# Реальные находки: semgrep может префиксовать путь конфигом или каталогом
# запуска, поэтому путь нормализуем по известным маркерам.
def normalize(path: str) -> str:
    for marker in ("sast-rules/", "fixtures/"):
        idx = path.find(marker)
        if idx >= 0:
            return path[idx + len(marker):]
    return path.lstrip("/")


actual = set()
for res in report.get("results") or []:
    rel = normalize(res.get("path", ""))
    line = res.get("start", {}).get("line", 0)
    check = res.get("check_id", "").rsplit(".", 1)[-1]
    actual.add((rel, line, check))

problems = []
for (rel, line), rule in expected_hit.items():
    if (rel, line, rule) not in actual:
        problems.append(f"НЕ СРАБОТАЛО: {rel}:{line} — ожидалась находка {rule}")
for (rel, line), rule in expected_clean.items():
    if (rel, line, rule) in actual:
        problems.append(f"ЛОЖНОЕ СРАБАТЫВАНИЕ: {rel}:{line} — {rule} сработало, ожидался пропуск")

# Находки без аннотаций — тоже расхождение: правило поймало то, что не описано.
annotated = set(expected_hit) | set(expected_clean)
for rel, line, check in sorted(actual):
    if (rel, line) not in annotated:
        problems.append(f"БЕЗ АННОТАЦИИ: {rel}:{line} — {check}")

print(f"правил в отчёте: {len({c for _, _, c in actual})}; "
      f"ожидалось находок: {len(expected_hit)}, пропусков: {len(expected_clean)}")
if problems:
    for p in problems:
        print(f"  {p}")
    print(f"расхождений: {len(problems)}")
    raise SystemExit(1)
print("все ожидания совпали")
PY
