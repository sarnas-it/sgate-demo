# Sarnas Security Gate — демо и пилот

Демонстрационный репозиторий для пилота **Security Gate** (проект SGATE,
заказчик — АльфаСтрахование). Здесь собраны работающие проверки из того, что
уже есть у Sarnas:

| Слой | Продукт | Что проверяет | Блокирует |
|---|---|---|---|
| SCA | **Deps** (GitHub App) | уязвимые версии пакетов, OSV, достижимость, план обновления | CRITICAL/HIGH |
| Секреты и ПДн | **Guardrail** (GitHub Action) | ключи, токены, пароли, персональные данные РФ в диффе | секреты |
| SAST | **Semgrep** | небезопасные конструкции в коде | ERROR |
| Контейнеры/IaC | **Trivy** | Dockerfile, конфигурация инфраструктуры | CRITICAL/HIGH |

Политика пилота: **CRITICAL/HIGH — блокировка, MODERATE — предупреждение,
исключение — только с владельцем и сроком.**

## Что специально сломано

В `main` намеренно стоит `next 16.3.8` — версия с двумя CRITICAL RCE
(`GHSA-2464-fhr4-w9xw`, `GHSA-673q-mjm6-r5xr`). Это baseline демо: Deps
находит 11 уязвимостей и создаёт issue «Зависимости: ежедневный отчёт об
уязвимостях» — ровно как в живом примере
[issue #152](https://github.com/sarnas-it/web-sarnas/issues/152).

> **Не используйте этот репозиторий как шаблон для продакшена.** Уязвимая
> зависимость и демонстрационный «секрет» лежат здесь намеренно.

## Сценарии демо

| # | Ветка / PR | Что происходит | Ожидаемый результат |
|---|---|---|---|
| 1 | `main` | ночной обход Deps | issue с 11 уязвимостями, 2 CRITICAL RCE |
| 2 | `demo/secret-leak` | в дифф добавлен ключ партнёра | Guardrail — **красный**, merge заблокирован |
| 3 | `demo/critical-dependency` | добавлен `minimist 1.2.5` | Deps check run — **красный**, CRITICAL |
| 4 | `demo/fix-next` | `next` обновлён до 16.4.5 | Deps — **зелёный**, CRITICAL больше нет |
| 5 | дашборд | `https://deps.sarnas.ru:8443` | репозитории, находки, история, стоимость |

Пошаговый сценарий показа — [`docs/05-demo-script.md`](docs/05-demo-script.md).

## Структура

```
app/                     демо-приложение Next.js (намеренно уязвимая версия)
lib/                     код, который используется в демо-ветках
.github/workflows/       security-gate: Guardrail + Semgrep + Trivy
guardrail.yml            правила Guardrail и исключения
Dockerfile               для Trivy config scan
scripts/local-gate.sh    локальный прогон гейта без GitHub Actions
docs/                    one-pager, план пилота, runbook, 152-ФЗ, сценарий демо
```

## Локальный прогон

Нужны собранные бинарники Deps и Guardrail:

```bash
# из соседних репозиториев
(cd ../repo-review-research/deps && go build -o /tmp/deps ./cmd/deps)
(cd ../guardrail && go build -o /tmp/guardrail ./cmd/guardrail)

DEPS_BIN=/tmp/deps GUARDRAIL_BIN=/tmp/guardrail \
  scripts/local-gate.sh origin/main HEAD
```

Скрипт печатает единую сводку и возвращает код 1, если есть блокирующие
находки. Это тот же контракт, что у CI: **упал любой слой — релиз не идёт.**

## Документы пилота

- [`docs/01-one-pager.md`](docs/01-one-pager.md) — что предлагаем Альфе.
- [`docs/02-pilot-plan.md`](docs/02-pilot-plan.md) — 3 недели, роли, критерии.
- [`docs/03-runbook.md`](docs/03-runbook.md) — как включить гейт у клиента.
- [`docs/04-on-prem-152fz.md`](docs/04-on-prem-152fz.md) — контур данных и 152-ФЗ.
- [`docs/05-demo-script.md`](docs/05-demo-script.md) — сценарий показа.
- [`docs/06-open-questions.md`](docs/06-open-questions.md) — что уточнить у Альфы.
