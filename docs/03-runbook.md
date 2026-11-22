# Runbook: включение Security Gate

Runbook для инженера внедрения. Все команды выполняются в репозитории
заказчика; секреты и токены не коммитятся.

## 0. Что нужно до старта

- [ ] владелец политики со стороны заказчика;
- [ ] 1–2 репозитория, доступ на чтение и запись (для PR/check run);
- [ ] платформа: GitHub, GitLab или Jenkins;
- [ ] решение: SaaS-дашборд или on-prem;
- [ ] список экосистем (npm, Go, Python, Java, Ruby);
- [ ] окно на разбор ложных срабатываний в первую неделю.

## 1. GitHub: SCA через Deps

1. Установить GitHub App `sarnas-deps-guard` на выбранные репозитории.
2. Добавить репозитории в `DEPSD_REPOS` на стороне Deps (или в
   `DEPSD_REVIEW_REPOS`, если нужен полный режим ревью).
3. Проверить вебхук: App → Advanced → Recent deliveries → событие
   `pull_request` доставлено.
4. Открыть тестовый PR, дождаться комментария и check run.
5. В branch protection включить обязательный check run Deps.

Проверка:

```bash
gh pr checks <номер>
gh pr view <номер> --comments
```

Ожидаемо: при CRITICAL/HIGH check run красный, в комментарии — пакет, версия,
advisory, исправленная версия.

## 2. GitHub: секреты и ПДн через Guardrail

Скопировать `.github/workflows/security-gate.yml` из демо-репозитория или
добавить один job:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: docker://ghcr.io/sarnas-it/guardrail:v0.1.0
  with:
    base: ${{ github.event.pull_request.base.sha || github.event.before }}
    head: ${{ github.sha }}
    config: guardrail.yml
    sarif_file: guardrail.sarif
```

`fetch-depth: 0` обязателен: Guardrail читает дифф между коммитами.

Проверка:

```bash
docker run --rm -v "$PWD:/repo" -w /repo \
  ghcr.io/sarnas-it/guardrail:v0.1.0 \
  scan --repo /repo --base origin/main --head HEAD --config guardrail.yml
```

Ожидаемо: exit 1 при найденном секрете; ПДн печатаются как предупреждения.

## 3. Semgrep (слой пилота)

```bash
docker run --rm -v "$PWD:/src" -w /src \
  semgrep/semgrep:1.186.0 \
  semgrep scan --config auto --metrics=off --sarif --output semgrep.sarif --error
```

Если политика заказчика запрещает публичные правила — заменить `--config auto`
на локальный набор правил (`--config ./semgrep-rules`).

## 4. Trivy (контейнеры и IaC)

```bash
docker run --rm -v "$PWD:/src" -w /src \
  aquasec/trivy:0.76.2 \
  config --severity CRITICAL,HIGH --exit-code 1 /src
```

Для образов:

```bash
trivy image --severity CRITICAL,HIGH --exit-code 1 <registry>/<image>:<tag>
```

## 5. Политика и исключения

Правило по умолчанию:

| Severity | Действие |
|---|---|
| CRITICAL | блокировка |
| HIGH | блокировка |
| MODERATE | предупреждение |
| LOW | отчёт |

Исключение оформляется только так:

```yaml
# guardrail.yml
ignore:
  matches:
    - rule: phone_ru
      path: "testdata/fixtures.go"
      reason: "тестовые данные, не ПДн"
```

или для Deps — через allowlist в конфигурации App. У каждого исключения есть
**владелец** и **срок пересмотра**. Исключение без срока удаляется при
следующем ревью.

## 6. Ежедневный режим

- утром проверить issue «Зависимости: ежедневный отчёт об уязвимостях»;
- новые CRITICAL/HIGH — в работу в тот же день;
- раз в неделю смотреть метрики: новые находки, закрытые, ложные
  срабатывания, заблокированные PR;
- раз в две недели пересматривать allowlist.

## 7. GitLab / Jenkins

Нативных адаптеров в пилоте нет. Порядок:

1. Собрать бинарники Deps и Guardrail (или использовать контейнер Guardrail).
2. Запускать в job:

```bash
guardrail scan --repo . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --head "$CI_COMMIT_SHA"
deps scan --repo . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --head "$CI_COMMIT_SHA" --json deps.json
```

3. Падать на exit code Guardrail и на разборе `deps.json` по политике
   (см. `scripts/local-gate.sh`).
4. Публиковать SARIF/JSON как артефакт job.

## 8. Откат

- выключить обязательность check run в branch protection — гейт остаётся в
  режиме отчёта;
- отключить job Guardrail в workflow;
- убрать репозиторий из списка Deps;
- ничего не удалять из истории: находки и исключения остаются в отчётах.

## 9. Диагностика

| Симптом | Что проверить |
|---|---|
| нет check run Deps | App установлен на репозиторий? репозиторий в списке? вебхук доставлен? |
| Guardrail всегда зелёный | `fetch-depth: 0`? правильные base/head? конфиг найден? |
| Guardrail падает на каждом PR | `ignore.paths`, `severity`, ложные срабатывания |
| Semgrep не находит ничего | язык поддерживается? правила загрузились? `--config` верный? |
| Trivy шумит | `--severity`, `.trivyignore`, `--ignore-unfixed` |
| Дашборд недоступен | DNS-запись, сертификат, Basic auth |

## 10. Контакты и эскалация

- инженер внедрения Sarnas — первый контакт по всем сбоям гейта;
- владелец политики заказчика — решения block/warn/исключения;
- владелец пилота — изменение объёма и сроков.

Эскалация: сбой гейта → инженер внедрения; спор о находке → владелец политики;
сроки → владельцы пилота.
