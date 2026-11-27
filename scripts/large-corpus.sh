#!/usr/bin/env bash
# Прогон большого квалификационного корпуса (10.2 в) по шардам.
#
# Один прогон на 10 млн строк упирается в память: semgrep и gosec убиваются
# OOM на ~4 ГБ RSS. Поэтому корпус режется на шарды, каждый считается
# отдельно, а метрики 10.4/10.5 суммируются.
#
# Использование:
#   scripts/large-corpus.sh [всего_строк] [строк_в_шарде] [конфиг]
#
# По умолчанию: 10 000 000 / 1 000 000 / analyzers.gost.yaml.
# Результат: /tmp/sgate-large-corpus/report.md и код 0, если агрегат
# укладывается в порог 8.4.

set -euo pipefail

total_lines="${1:-10000000}"
shard_lines="${2:-1000000}"
config="${3:-analyzers.gost.yaml}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${WORK_DIR:-/tmp/sgate-large-corpus}"
file_lines=500

if [ "$shard_lines" -lt 100000 ]; then
  echo "шард меньше 100k строк: subprocess-запуски становятся дороже самого анализа" >&2
  exit 2
fi

files_per_shard=$(( shard_lines / file_lines ))
defect_files=$(( files_per_shard * 8 / 10 ))
clean_files=$(( files_per_shard - defect_files ))
shards=$(( (total_lines + shard_lines - 1) / shard_lines ))

rm -rf "$work"
mkdir -p "$work"

cd "$root/core"

for i in $(seq 1 "$shards"); do
  dir="$work/shard-$i"
  echo "== шард $i/$shards: генерация"
  go run ./cmd/corpusgen -out "$dir" \
    -defect-files "$defect_files" -clean-files "$clean_files" -file-lines "$file_lines"

  echo "== шард $i/$shards: прогон SGATE"
  runs="$work/runs-$i"
  set +e
  go run ./cmd/sgate -repo "$dir" -config "$config" \
    -format json -record "$runs" >/dev/null 2>"$work/shard-$i.err"
  code=$?
  set -e
  # 1 — есть блокирующие находки, это ожидаемо: корпус состоит из ошибок.
  if [ "$code" -gt 1 ]; then
    echo "шард $i: SGATE завершился с кодом $code" >&2
    tail -5 "$work/shard-$i.err" >&2
    exit 2
  fi

  run_dir=$(ls -d "$runs"/*/ | sort | tail -1)
  go run ./cmd/sgate quality -run "$run_dir" -manifest "$dir/manifest.json" \
    -format json -out "$work/shard-$i.quality.json" >/dev/null 2>&1 || true
  if [ ! -s "$work/shard-$i.quality.json" ]; then
    echo "шард $i: нет отчёта качества" >&2
    exit 2
  fi
done

python3 - "$work" "$shards" "$total_lines" <<'PY'
import json
import pathlib
import sys

work, shards, total = pathlib.Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
rows = []
tot = {"tb": 0, "tp": 0, "fn": 0, "fp": 0, "tw": 0}
for i in range(1, shards + 1):
    m = json.loads((work / f"shard-{i}.quality.json").read_text())
    row = {k: int(m.get(k, 0)) for k in tot}
    rows.append((i, row))
    for k in tot:
        tot[k] += row[k]

def rate(part, whole):
    return 100.0 * part / whole if whole else 0.0

fp_rate = rate(tot["fp"], tot["tw"])
fn_rate = rate(tot["fn"], tot["tb"])
passed = fp_rate <= 50 and fn_rate <= 50

lines = [
    "# Крупный корпус (10.2 в): шардированный прогон",
    "",
    f"Строк в корпусе: {total}, шардов: {shards}, по {total // shards} строк.",
    "",
    "| Шард | TB | TP | FN | TW | FP |",
    "|---:|---:|---:|---:|---:|---:|",
]
for i, r in rows:
    lines.append(f"| {i} | {r['tb']} | {r['tp']} | {r['fn']} | {r['tw']} | {r['fp']} |")
lines += [
    f"| **Итого** | **{tot['tb']}** | **{tot['tp']}** | **{tot['fn']}** | **{tot['tw']}** | **{tot['fp']}** |",
    "",
    f"FP = {fp_rate:.1f} %, FN = {fn_rate:.1f} %, порог 8.4: {'пройден' if passed else 'НЕ пройден'}.",
]
report = "\n".join(lines) + "\n"
(work / "report.md").write_text(report)
print(report)
raise SystemExit(0 if passed else 1)
PY
