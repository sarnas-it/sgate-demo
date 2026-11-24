# Закрытый DAST-пилот: runbook

## 1. Стенд

```bash
docker compose -p sgate-tt -f /tmp/compose-tt-stand.yml up -d
```

Стенд: `http://127.0.0.1:18081`, Postgres 15433, MinIO 19000/19001.
Проверка: `/healthz` 200, `/` 200.

## 2. Тестовые роли

- `pilot-admin@example.com` — instance admin;
- `pilot-user@example.com` — пользователь;
- `pilot-guest@example.com` — гость.

Пароль — только тестовый, хранится в env/секрете стенда, не в git.

## 3. Scope

```yaml
target: http://127.0.0.1:18081
allowed_hosts: [127.0.0.1]
max_rps: 2
auth:
  mode: bearer
  token_env: DAST_TOKEN
  test_accounts_only: true
```

## 4. Прогон

```bash
cd core
DAST_TOKEN=... DAST_CONFIRM=1 go run ./cmd/sgatedast passive ... -findings-out ...
DAST_TOKEN=... DAST_CONFIRM=1 go run ./cmd/sgatedast scan ... -id zap-full ... -findings-out ...
DAST_TOKEN=... DAST_CONFIRM=1 go run ./cmd/sgatedast scan ... -id feroxbuster-tt ... -findings-out ...
DAST_TOKEN=... DAST_CONFIRM=1 go run ./cmd/sgatedast scan ... -id nuclei-offline ... -findings-out ...
go run ./cmd/sgatedast report ... -policy ../dast/policy.tasktracker.yaml
```

Отчёт: `dast-out/report.md`, `report.sarif`.

## 5. Политика

- block critical/high;
- warn medium;
- ignore low/info;
- исключения только с owner/expires.

Проверка блокировки: добавить synthetic high в findings JSONL → report exit 1.

## 6. Очистка

```bash
docker compose -p sgate-tt down -v
rm -rf /tmp/dast-tt* /tmp/scope-tt*.yaml
```

Тестовые данные удаляются вместе с volume. Прод не затрагивается.

## 7. Ограничения

- только тестовый стенд/письменный scope;
- full scan с header replacer, не form-login context;
- nuclei — только локальные шаблоны;
- ferox — словарь TaskTracker, 404 отфильтрованы.
