#!/usr/bin/env python3
"""Политика гейта: CRITICAL/HIGH блокируют, остальное — предупреждение.

Читает JSON-отчёт `deps scan` и печатает сводку. Код 1 — есть блокирующие
находки. Используется и локальным демо, и CI.
"""

from __future__ import annotations

import json
import sys

BLOCK = {"CRITICAL", "HIGH"}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: policy.py <deps-report.json>", file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)

    findings: list[tuple[str, str, str, str]] = []
    for package in report.get("vulnerable") or []:
        for advisory in package.get("advisories") or []:
            findings.append(
                (
                    package.get("name", "?"),
                    package.get("version", "?"),
                    advisory.get("severity", "UNKNOWN"),
                    advisory.get("id", "?"),
                )
            )

    blocking = [f for f in findings if f[2] in BLOCK]
    warning = [f for f in findings if f[2] not in BLOCK]

    for name, version, severity, advisory in findings:
        action = "BLOCK" if severity in BLOCK else "warn "
        print(f"[{action}] {name} {version} — {severity} — {advisory}")

    print(
        f"итог: {len(blocking)} блокирующих, {len(warning)} предупреждений",
        file=sys.stderr,
    )
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
