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

## Каталог сканеров

Образы закреплены по digest; каталог — `dast/scanners.lock`, проверка — `scripts/check-pins.sh`.

## Passive WSTG

```bash
cd core
go run ./cmd/sgatedast passive -scope ../dast/scope.example.yaml \
  -out ../dast/out/passive.json
```

Проверяет заголовки, cookies и открытые служебные файлы. Без payload'ов.
На Juice Shop: CSP/Referrer-Policy/Permissions-Policy, 0 блокирующих; `.env`
на SPA не считается открытым, если ответ — HTML.

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

ZAP full с auth (тестовая учётка):

```bash
DAST_TOKEN=... go run ./cmd/sgatedast scan \
  -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml -id zap-full -out ../dast/out -confirm
```

`zap-full` подставляет `Authorization: Bearer` через replacer; только тестовые
учётки.

Nuclei и feroxbuster:

```bash
go run ./cmd/sgatedast scan -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml -id nuclei -out ../dast/out -confirm

go run ./cmd/sgatedast scan -scope ../dast/scope.example.yaml \
  -scanners ../dast/scanners.yaml -id feroxbuster -out ../dast/out -confirm
```

На Juice Shop: feroxbuster нашёл 5 путей (info), nuclei high/critical — 0.

## Политика

```bash
go run ./cmd/sgatedast scan ... -policy ../dast/policy.yaml
```

`block: [critical, high]`, `warn: [medium]`, `ignore: [low, info]`.
Исключение требует `owner` и `expires`; просроченное не действует.

## SARIF

`sgatedast scan|passive -sarif-out out.sarif` — единый SARIF для GitHub Security.

## Отчёт и WSTG

Каждый `scan` пишет `dast/out/report.md`: сводка по severity, таблица находок,
карта покрытия OWASP WSTG и ограничения. `-report` задаёт другой путь.

## Дедуп

Точные повторы убираются. ZAP и nuclei на один URL с одним CWE склеиваются:
`file + CWE`. Разные CWE или разные URL остаются раздельно.

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
