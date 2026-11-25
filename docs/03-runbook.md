# Runbook: включение Security Gate

Runbook для инженера внедрения. Все команды выполняются в репозитории, где включается гейт; секреты и токены не коммитятся.

## 0. Что нужно до старта

- [ ] владелец политики со стороны организации;
- [ ] 1–2 репозитория, доступ на чтение и запись (для PR/check run);
- [ ] платформа: GitHub, GitLab или Jenkins;
- [ ] решение: SaaS-дашборд или on-prem;
- [ ] список экосистем (npm, Go, Python, Java, Ruby);
- [ ] окно на разбор ложных срабатываний в первую неделю;
- [ ] машина для сборки офлайн-пакета баз (с интернетом) или доступ к
      готовому пакету Sarnas.

## 1. Офлайн-пакет баз

Пакет собирается там, где есть интернет, и переносится в целевой контур.

```bash
export DEPS_SIGN_KEY=<64 hex-символа, ключ Sarnas>
deps sync --out ./dataset --ecosystems npm,Go
```

Получается каталог с `manifest.json`, подписью и gzip-JSONL индексами OSV/БДУ.
В контуре:

```bash
deps scan --repo . --worktree \
  --dataset /opt/sgate/dataset \
  --max-age 336h \
  --min-severity HIGH --json /tmp/sca.json
python3 scripts/policy.py /tmp/sca.json
```

- `--max-age` — предел свежести; по умолчанию 336 часов (14 суток). Просроченный
  пакет отвергается, а не считается «уязвимостей нет».
- Подпись проверяется автоматически; для сборок без вшитого ключа —
  `--pubkey-hex`.
- Обновление: раз в сутки/неделю по регламенту, через прокси или перенос
  файла. Старый пакет сохраняется до успешной замены.

### Достижимость уязвимостей (SCA-reachability)

Полный список advisories без достижимости — это шум: в пилоте Jxls-report
18 advisories, из которых реально достижимы 8 high у `excelize` (он парсит
недоверенный XLSX), а `compress` не импортируется вовсе. Deps умеет
ранжировать находки по достижимости:

```bash
deps scan --repo . --worktree --govulncheck \
  --dataset /opt/sgate/dataset \
  --max-age 336h --min-severity MODERATE --json /tmp/sca.json
```

- `--worktree` — читать исходники рабочей копии (без него достижимость не
  оценивается);
- `--govulncheck` — символьная достижимость для Go: `govulncheck` должен быть
  в `PATH` (или в образе), иначе шаг пропускается с предупреждением;
- в отчёте появляется `reach_top` у пакета и `reach` у каждого advisory:
  `reachable` (уязвимая функция вызывается), `possible` (пакет импортируется,
  вызов не найден), `unlikely` (пакет не импортируется), `unknown`.

Порядок разбора: сначала `reachable`, затем `possible`; `unlikely` закрывается
обновлением по регламенту, без отдельного SLA. Вердикт — свидетельство, а не
приговор: `possible` остаётся в отчёте, чтобы его можно было проверить руками.

Для npm без `govulncheck` достижимость оценивается моделью (`--llm` требует
ключа) или остаётся `unknown` — тогда разбор идёт по severity, как раньше.

## 2. GitHub: SCA через Deps

1. Установить GitHub App `sarnas-deps-guard` на выбранные репозитории.
2. Добавить репозитории в `DEPSD_REPOS` на стороне Deps (или в
   `DEPSD_REVIEW_REPOS`, если нужен полный режим ревью).
3. Проверить вебхук: App → Advanced → Recent deliveries → событие
   `pull_request` доставлено.
4. Открыть тестовый PR, дождаться комментария и check run.
5. В branch protection включить обязательный check run Deps.

Для офлайн-режима App работает с пакетом баз на своём хосте; вебхук и check run
идут через GitHub, а данные о зависимостях — только в локальную базу.

Проверка:

```bash
gh pr checks <номер>
gh pr view <номер> --comments
```

Ожидаемо: при CRITICAL/HIGH check run красный, в комментарии — пакет, версия,
advisory, исправленная версия.

## 3. GitHub: секреты и ПДн через Guardrail

Добавить job:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: docker://ghcr.io/sarnas-it/guardrail:v0.1.0
  with:
    base: ${{ github.event.pull_request.base.sha || github.event.before }}
    head: ${{ github.sha }}
    config: guardrail.yml
```

`fetch-depth: 0` обязателен: Guardrail читает дифф между коммитами.

Для блокировки ПДн, а не предупреждения, в `guardrail.yml`:

```yaml
severity:
  phone_ru: block
  email: block
  inn_ru: block
  snils_ru: block
  passport_ru: block
  full_name_ru: block
```

Проверка:

```bash
docker run --rm -v "$PWD:/repo" -w /repo \
  ghcr.io/sarnas-it/guardrail:v0.1.0 \
  scan --repo /repo --base origin/main --head HEAD --config guardrail.yml
```

Ожидаемо: exit 1 при секрете или ПДн; значения в выводе замаскированы.

## 4. Политика и исключения

Правило по умолчанию:

| Находка | Действие |
|---|---|
| Секрет | блокировка |
| ПДн | блокировка |
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

## 5. Ежедневный режим

- утром проверить issue «Зависимости: ежедневный отчёт об уязвимостях»;
- новые CRITICAL/HIGH — в работу в тот же день;
- раз в неделю смотреть метрики: новые находки, закрытые, ложные
  срабатывания, заблокированные PR;
- раз в две недели пересматривать allowlist;
- проверять свежесть офлайн-пакета баз.

## 6. GitLab / Jenkins

Нативных адаптеров в пилоте нет. Порядок:

1. Собрать бинарники Deps и Guardrail (или использовать контейнер Guardrail).
2. Запускать в job:

```bash
guardrail scan --repo . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --head "$CI_COMMIT_SHA"
deps scan --repo . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --head "$CI_COMMIT_SHA" \
  --dataset /opt/sgate/dataset --json deps.json
python3 scripts/policy.py deps.json
```

3. Падать на exit code Guardrail и на exit code политики Deps.
4. Публиковать SARIF/JSON как артефакт job.

## 7. Откат

- выключить обязательность check run в branch protection — гейт остаётся в
  режиме отчёта;
- отключить job Guardrail в workflow;
- убрать репозиторий из списка Deps;
- ничего не удалять из истории: находки и исключения остаются в отчётах.

## 8. Диагностика

| Симптом | Что проверить |
|---|---|
| нет check run Deps | App установлен на репозиторий? репозиторий в списке? вебхук доставлен? |
| Deps пишет «пакет устарел» | дата сборки пакета, `--max-age`, регламент обновления |
| Deps не видит уязвимость | экосистема есть в пакете? версия пакета в lock-файле? |
| Guardrail всегда зелёный | `fetch-depth: 0`? правильные base/head? конфиг найден? |
| Guardrail падает на каждом PR | `ignore.paths`, `severity`, ложные срабатывания |
| Секрет в логе | `GUARDRAIL_REVEAL` выключен? маскирование работает? |
| Дашборд недоступен | DNS-запись, сертификат, Basic auth |

## 9. Контакты и эскалация

- инженер внедрения Sarnas — первый контакт по всем сбоям гейта;
- владелец политики со стороны организации — решения block/warn/исключения;
- владелец пилота — изменение объёма и сроков.

Эскалация: сбой гейта → инженер внедрения; спор о находке → владелец политики;
сроки → владельцы пилота.
