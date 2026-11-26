#!/usr/bin/env python3
"""Command astpy — второй AST-модуль SGATE (Python).

Контракт анализатора:
  SGATE_REPO  — корень репозитория (или -repo)
  SGATE_OUT   — путь к SARIF-отчёту (или -out)

Пишет SARIF 2.1.0, печатает «py-ast-scanned: <файл>» на каждый
проанализированный файл (по нему coverage guard отличает «чисто» от
«не сканировано»). Код возврата 0 — прогон состоялся, 2 — внутренняя ошибка.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402


def level(severity: str) -> str:
    if severity == "HIGH":
        return "error"
    if severity == "LOW":
        return "note"
    return "warning"


def write_sarif(path: Path, findings: list[rules.Finding]) -> None:
    rules_out = []
    for r in rules.catalog():
        rules_out.append({
            "id": r["id"],
            "shortDescription": {"text": r["message"]},
            "defaultConfiguration": {"level": level(r["severity"])},
            "properties": {"severity": r["severity"], "cwe": r["cwe"]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule,
            "level": level(f.severity),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
        })
    report = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "sgate-astpy", "rules": rules_out}},
            "results": results,
        }],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-repo", default=os.environ.get("SGATE_REPO", ""))
    parser.add_argument("-out", default=os.environ.get("SGATE_OUT", ""))
    parser.add_argument("-quiet", action="store_true")
    args = parser.parse_args()

    if not args.repo or not args.out:
        print("astpy: нужны SGATE_REPO и SGATE_OUT (или -repo/-out)", file=sys.stderr)
        return 2
    root = Path(args.repo)
    if not root.is_dir():
        print(f"astpy: репозиторий недоступен: {root}", file=sys.stderr)
        return 2

    findings, scanned = rules.analyze(str(root))
    if not args.quiet:
        for rel in scanned:
            print(f"py-ast-scanned: {rel}", file=sys.stderr)
    try:
        write_sarif(Path(args.out), findings)
    except OSError as exc:
        print(f"astpy: {exc}", file=sys.stderr)
        return 2
    print(f"astpy: файлов {len(scanned)}, находок {len(findings)}, отчёт {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
