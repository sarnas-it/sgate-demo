#!/usr/bin/env bash
# Собирает слой корпуса 10.2 в) из реальных проектов.
#
# Спецификация (JSON):
#   {
#     "version": 1,
#     "entries": [
#       {
#         "name": "project-short-name",
#         "repo": "https://github.com/org/project.git",
#         "commit": "<pre-fix sha>",
#         "cve": "CVE-XXXX-YYYY",
#         "files": ["internal/api/handler.go", "go.mod"],
#         "defects": [{"file": "internal/api/handler.go", "line": 42,
#                      "type": "6.3а", "cwe": "CWE-89", "note": "..."}],
#         "clean": ["internal/api/middleware.go"]
#       }
#     ]
#   }
#
# Вместо repo/commit можно указать "local": "/path/to/checkout" — для
# офлайн-прогона и уже разобранных пилотов.
#
# Использование:
#   scripts/fetch-real-corpus.sh spec.json out/ [cache-dir]
#
# Код возврата 0 — корпус собран, 2 — ошибка спецификации/клонирования.

set -euo pipefail

spec="${1:?usage: fetch-real-corpus.sh <spec.json> <out-dir> [cache-dir]}"
out="${2:?usage: fetch-real-corpus.sh <spec.json> <out-dir> [cache-dir]}"
cache="${3:-.real-corpus-cache}"

if [ ! -f "$spec" ]; then
  echo "нет спецификации: $spec" >&2
  exit 2
fi

mkdir -p "$out" "$cache"
rm -rf "${out:?}"/*

python3 - "$spec" "$out" "$cache" <<'PY'
import json
import pathlib
import shutil
import subprocess
import sys

spec_path, out_dir, cache_dir = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
spec = json.load(open(spec_path, encoding="utf-8"))
if spec.get("version") != 1:
    print(f"unsupported spec version: {spec.get('version')}", file=sys.stderr)
    raise SystemExit(2)

manifest = {"version": 1, "tolerance": 2, "clean": [], "defects": []}
total_files = 0

for entry in spec.get("entries") or []:
    name = entry.get("name", "").strip()
    if not name:
        print("entry without name", file=sys.stderr)
        raise SystemExit(2)
    dest = out_dir / name
    dest.mkdir(parents=True, exist_ok=True)

    files = entry.get("files") or []
    if not files:
        print(f"{name}: files is empty — нечего копировать", file=sys.stderr)
        raise SystemExit(2)

    local = entry.get("local")
    if local:
        src = pathlib.Path(local).expanduser()
        if not src.is_dir():
            print(f"{name}: local path not found: {src}", file=sys.stderr)
            raise SystemExit(2)
        for rel in files:
            from_path = src / rel
            if not from_path.exists():
                print(f"{name}: нет файла {rel} в {src}", file=sys.stderr)
                raise SystemExit(2)
            to_path = dest / rel
            to_path.parent.mkdir(parents=True, exist_ok=True)
            if from_path.is_dir():
                shutil.copytree(from_path, to_path, dirs_exist_ok=True)
            else:
                shutil.copy2(from_path, to_path)
            total_files += 1
    else:
        repo, commit = entry.get("repo", ""), entry.get("commit", "")
        if not repo or not commit:
            print(f"{name}: нужны repo+commit или local", file=sys.stderr)
            raise SystemExit(2)
        repo_dir = cache_dir / name
        if not repo_dir.is_dir():
            subprocess.run(
                ["git", "clone", "--filter=blob:none", "--no-checkout", repo, str(repo_dir)],
                check=True,
            )
        subprocess.run(["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin", commit], check=True)
        for rel in files:
            blob = subprocess.run(
                ["git", "-C", str(repo_dir), "show", f"{commit}:{rel}"],
                check=True, capture_output=True,
            ).stdout
            to_path = dest / rel
            to_path.parent.mkdir(parents=True, exist_ok=True)
            to_path.write_bytes(blob)
            total_files += 1

    for d in entry.get("defects") or []:
        manifest["defects"].append({
            "file": f"{name}/{d['file']}",
            "line": int(d["line"]),
            "type": d.get("type", ""),
            "cwe": d.get("cwe", ""),
            "note": d.get("note", ""),
        })
    for c in entry.get("clean") or []:
        manifest["clean"].append(f"{name}/{c}")

manifest_path = out_dir / "manifest.json"
manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"real-corpus: проектов {len(spec.get('entries') or [])}, файлов {total_files}, "
      f"дефектов {len(manifest['defects'])}, чистых {len(manifest['clean'])}")
PY
