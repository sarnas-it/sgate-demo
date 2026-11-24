# DAST runbook

## Роли

- **Инженер ИБ** — scope, запуск, разбор находок, отчёт.
- **DevOps** — стенд, сеть, тестовые учётки, окно.
- **Владелец приложения** — исправления, подтверждение FP.
- **Владелец политики** — что блокирует релиз, исключения и сроки.

## 1. До запуска

- [ ] цель в `dast/scope.yaml`, allowlist и exclusions заполнены;
- [ ] письменное согласие владельца цели;
- [ ] окно сканирования;
- [ ] тестовые учётки, не прод;
- [ ] rate limit 5 rps и kill switch проверены;
- [ ] отчёты складываются в контур.

## 2. Стенд

```bash
./dast/stand-up.sh
```

Проверка: `curl -I http://127.0.0.1:3000` → 200.

## 3. Discovery

```bash
cd core
go run ./cmd/sgatedast discover \
  -scope ../dast/scope.yaml \
  -out ../dast/out/urls.txt
```

## 4. ZAP baseline

```bash
DAST_CONFIRM=1 go run ./cmd/sgatedast scan \
  -scope ../dast/scope.yaml \
  -scanners ../dast/scanners.yaml \
  -id zap-baseline -policy ../dast/policy.yaml -out ../dast/out
```

## 5. Auth и full scan (B5+)

```bash
DAST_TOKEN=... DAST_CONFIRM=1 go run ./cmd/sgatedast scan ... -id zap-full
```

Только тестовые учётки. Матрица ролей — `dast/auth.md`.

## 6. Дополнительные сканеры

```bash
go run ./cmd/sgatedast scan ... -id nuclei ...
go run ./cmd/sgatedast scan ... -id feroxbuster ...
```

## 7. Триаж

| Severity | Действие | Срок |
|---|---|---|
| critical | остановить релиз, чинить | 24 часа |
| high | блокировка, чинить | 7 дней |
| medium | предупреждение, план | 30 дней |
| low/info | в бэклог | по приоритету |

FP оформляется как исключение в `dast/policy.yaml`: rule/path, owner, expires, reason.

## 8. Отчёт

`dast/out/report.md`:

- severity и таблица находок;
- покрытие WSTG: проверено/частично/не проверено;
- ограничения.

Отчёт не является пентестом и не гарантирует отсутствие уязвимостей.

## 9. Метрики

- находок по severity;
- подтверждённых и FP;
- время до исправления;
- заблокированных релизов;
- покрытие WSTG.

## 10. Откат

```bash
./dast/stand-down.sh
```

При деградации стенда или 5xx — остановить прогон, зафиксировать время и цель.
