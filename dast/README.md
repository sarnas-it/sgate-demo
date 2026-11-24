# DAST: правила и стенд

Активные проверки SGATE запускаются только на тестовом стенде или на цели,
которая письменно согласована. Это не «настройка по умолчанию» — это условие
запуска.

## Разрешено

- локальный стенд Juice Shop/DVWA из `dast/stand`;
- тестовый контур заказчика с письменным согласием и списком целей;
- тестовые учётные записи, выданные для сканирования.

## Запрещено

- продакшен без письменного согласия и окна;
- чужие домены, IP и API;
- реальные персональные данные и прод-секреты;
- обход авторизации на реальных пользователях;
- скрытый запуск: каждый прогон должен быть в журнале.

## Обязательный чек-лист перед запуском

- [ ] цель входит в allowlist;
- [ ] есть письменное согласие владельца;
- [ ] окно сканирования согласовано;
- [ ] тестовые учётки, не прод;
- [ ] rate limit и kill switch проверены;
- [ ] логи и отчёты остаются в контуре.

## Ограничения

- rate limit по умолчанию — 5 запросов/сек на цель;
- запрещены разрушительные методы (`DELETE`, массовые `POST`) без отдельного согласия;
- при ошибках 5xx или деградации стенда — остановить прогон;
- kill switch: `Ctrl+C` или `docker compose down`; ZAP запускается отдельным контейнером.

## Auth

Секреты не хранятся в scope — только имя env-переменной:

```yaml
auth:
  mode: bearer          # none | bearer | header | cookie
  token_env: DAST_TOKEN
  test_accounts_only: true
```

```bash
DAST_TOKEN=... go run ./cmd/sgatedast scan ... -id nuclei
```

`bearer` → `Authorization: Bearer …`, `header` → указанный заголовок,
`cookie` → `Cookie: …`. Если auth нет, `-H` из команды сканера убирается.
Только тестовые учётки, только стенд. Матрица ролей — `dast/auth.md`.

## Discovery целей

```bash
cd core
go run ./cmd/sgatedast --scope ../dast/scope.example.yaml --out ../dast/out/urls.txt
```

Собирает ссылки с главной, `sitemap.xml`, `openapi.json`, `swagger.json` и
фильтрует по scope. Для SPA вида Juice Shop HTML даёт только ассеты — реальные
маршруты добавляются из OpenAPI/списка или crawl с браузером (B3+).

## Запуск ZAP baseline

```bash
./dast/stand-up.sh
cd core
go run ./cmd/sgatedast scan \
  -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml \
  -id zap-baseline -out ../dast/out -confirm
```

Проверено на Juice Shop: 38 находок ZAP, 0 блокирующих (baseline даёт
предупреждения). Для активных high/critical нужен full scan и auth — B5.

Nuclei и feroxbuster:

```bash
go run ./cmd/sgatedast scan -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml -id nuclei -out ../dast/out -confirm

go run ./cmd/sgatedast scan -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml -id feroxbuster -out ../dast/out -confirm
```

На Juice Shop: feroxbuster нашёл 5 путей (info), nuclei high/critical — 0.

## Артефакты

- `report.json`, `report.md`, `report.html` — в `dast/out/`;
- в SGATE попадают только нормализованные находки: endpoint, класс, CWE, severity;
- сырые запросы/ответы не уходят во внешние сервисы.

## Быстрый старт

```bash
./dast/stand-up.sh
DAST_CONFIRM=1 ./dast/run-baseline.sh
./dast/stand-down.sh
```
