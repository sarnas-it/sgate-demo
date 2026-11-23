# Sarnas Security Gate — демо

Самопроверяющееся демо сервиса **Security Gate** (проект SGATE). Показывает два слоя, которые входят в сервис:

| Слой | Продукт | Что проверяет | Блокирует | Сеть |
|---|---|---|---|---|
| SCA | **Deps** | уязвимые версии пакетов по офлайн-базе OSV | CRITICAL/HIGH | не нужна |
| Секреты и ПДн | **Guardrail** | ключи, токены, пароли, телефоны, email, ИНН, СНИЛС, паспорт в диффе | любая находка | не нужна |

**Контракт:** нашли блокирующую находку — пайп остановлен. Не нашли — пайп
идёт дальше. Оба слоя работают внутри контура: ни код, ни имена пакетов
наружу не уходят.

SAST (Semgrep) и контейнеры (Trivy) **не входят в ядро сервиса** — это
отдельные слои на будущее, в демо и пилот не заявляются.

## Быстрая проверка

```bash
scripts/demo.sh
```

Скрипт собирает Deps и Guardrail, затем прогоняет пять сценариев в Docker с
`--network none` и сам проверяет результат:

| # | Сценарий | Ожидание |
|---|---|---|
| 1 | секрет в PR (`demo/secret-leak`) | Guardrail остановил пайп |
| 2 | ПДн в PR (`demo/pii-leak`) | Guardrail остановил пайп |
| 3 | CRITICAL-зависимость (`demo/critical-dependency`) | Deps остановил пайп |
| 4 | исправление `next` (`demo/fix-next`) | Deps пропустил |
| 5 | чистый дифф (`demo/fix-next`) | Guardrail пропустил |

Код 0 — все сценарии повели себя как ожидалось. Логи — в `.demo-out/`.

## Что специально сломано

- В `main` стоит `next 16.3.8` — версия с CRITICAL RCE
  (`GHSA-2464-fhr4-w9xw`, `GHSA-673q-mjm6-r5xr`). Это baseline: Deps находит
  уязвимости и создаёт issue «Зависимости: ежедневный отчёт», как в живом
  примере [issue #152](https://github.com/sarnas-it/web-sarnas/issues/152).
- В ветках `demo/*` лежат вымышленные секрет и персональные данные — только
  для показа гейта. В продакшене так делать нельзя.

## Как устроен офлайн-режим

- **Deps** читает подписанный пакет баз `fixtures/osv-dataset/` (`--dataset`):
  внутри gzip-JSONL с записями OSV и манифест с подписью Ed25519. Сеть не
  используется; свежесть пакета проверяется (`--max-age`).
- **Guardrail** работает в раннере и не делает сетевых вызовов: читает дифф
  через git и применяет правила.
- Демо запускает оба бинарника в контейнере с `--network none` — это и есть
  доказательство «наружу ничего не уходит».

Пакет баз в репозитории — демонстрационный (10 записей OSV, ключ подписи
одноразовый). Для продакшена пакет собирается командой `deps sync` и
подписывается ключом Sarnas.

## Структура

```
app/                     демо-приложение Next.js (намеренно уязвимая версия)
lib/                     код демо-веток: секрет, ПДн, уязвимая зависимость
.github/workflows/       security-gate: Guardrail + Deps на GitHub-hosted раннере
fixtures/osv-dataset/    офлайн-пакет OSV для демо (подписан)
scripts/demo.sh          самопроверяющееся демо (5 сценариев)
scripts/build-tools.sh   сборка Deps и Guardrail
scripts/policy.py        политика block/warn по JSON-отчёту Deps
guardrail.yml            правила Guardrail и политика block
Dockerfile               приложение (для полноты, в ядро гейта не входит)
docs/                    one-pager, план пилота, runbook, 152-ФЗ, сценарий
```

## Ручной прогон одного слоя

```bash
# SCA офлайн
.tools/deps scan --repo . --worktree \
  --dataset fixtures/osv-dataset \
  --pubkey-hex "$(cat fixtures/osv-dataset/pubkey.hex)" \
  --max-age 87600h --min-severity HIGH

# секреты/ПДн в диффе
.tools/guardrail scan --repo . --base main --head demo/secret-leak --config guardrail.yml
```

Оба возвращают 0/1 по политике: Deps считает блокирующие находки через
`scripts/policy.py`, Guardrail — сам.

## Документы пилота

- [`docs/01-one-pager.md`](docs/01-one-pager.md) — что предлагаем.
- [`docs/02-pilot-plan.md`](docs/02-pilot-plan.md) — 3 недели, роли, критерии.
- [`docs/03-runbook.md`](docs/03-runbook.md) — как включить гейт у клиента.
- [`docs/04-on-prem-152fz.md`](docs/04-on-prem-152fz.md) — контур данных и 152-ФЗ.
- [`docs/05-demo-script.md`](docs/05-demo-script.md) — сценарий показа.
- [`docs/06-open-questions.md`](docs/06-open-questions.md) — что уточнить.
