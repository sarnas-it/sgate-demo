# ADR 0004: единая модель находок SAST/DAST

## Контекст

SAST (`sgate`) и DAST (`sgatedast`) выдают разные форматы: SARIF, ZAP JSON,
nuclei JSONL, ferox JSONL. Политика блокировки должна быть общей.

## Решение

- Обе линии нормализуют находки в `internal/sarif.Finding`: analyzer, rule,
  severity, message, file/URL, line, fingerprint, CWE, baseline.
- `internal/policy.Rank` и `Blocking` — общий порог.
- SAST отдаёт SARIF через `sgate --format sarif`.
- DAST отдаёт SARIF через `sgatedast scan|passive -sarif-out`.
- Baseline/suppressions работают для SAST; DAST-исключения — через
  `dast/policy.yaml` с owner/expires.
- Кросс-слойная склейка SAST↔DAST не автоматическая: у них разные ключи
  (файл/строка vs URL).

## Следствия

- один SARIF и один policy для отчёта и GitHub Security;
- severity и fingerprint считаются одинаково;
- DAST можно загрузить в GitHub Security тем же upload-sarif.
