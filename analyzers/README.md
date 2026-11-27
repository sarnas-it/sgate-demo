# Анализаторы SGATE

Анализатор — **отдельный модуль**, а не часть ядра. Ядро (`core/`) не знает
внутренностей анализатора: оно запускает команду или контейнер и читает SARIF.
Поэтому язык анализа можно менять (Go AST, PHP AST, JS AST, внешний продукт),
не трогая `core`, — меняется только запись в `core/analyzers.yaml`.

## Контракт

| Что | Как |
|---|---|
| Вход | `SGATE_REPO` — корень репозитория; `SGATE_OUT` — путь к SARIF-отчёту |
| Выход | SARIF 2.1.0 в `SGATE_OUT` |
| Прогресс | строка `ast-scanned: <файл>` (или своя, указанная в `scanned_regex`) на каждый проанализированный файл |
| Код возврата | `0` — прогон состоялся; `2` — внутренняя ошибка (битый отчёт, нет входа) |
| Находки | **не влияют** на код возврата: политика (`--block high`) — дело SGATE |
| Сеть | не нужна; анализатор работает офлайн |

Покрытие обязательно: SGATE отличает «чисто» от «анализатор ничего не
просканировал» по `scanned_regex` + `min_scanned_files` (или
`require_artifacts`). Если анализатор печатает не строку на файл, а итог
(«Ran 9 rules on 33 files»), ставится `scanned_total: true` — тогда из
группы берётся число, а не количество совпадений. Анализатор без маркера прогресса при нуле находок
считается подозрительным — это прямое следствие двух «ложных нулей» в пилотах.

## Подключение

```yaml
  - id: ast
    languages: [go]
    requires: [go.mod]
    runtime: command
    command: [go, run, ./analyzers/ast]
    output: .sgate-ast.sarif
    scanned_regex: 'ast-scanned: (\S+)'
    min_scanned_files: 1
```

- `runtime: command` — локальный бинарь/`go run`; `runtime: docker` — образ по
  digest, если анализатор тянет зависимости.
- `languages` — для каких языков запускать (SGATE определяет языки по файлам).
- `requires` — без какого файла анализатор не имеет смысла (`go.mod`).
- `fail_on` — подстроки, при которых прогон считается сбоем даже при коде 0.

## Как добавить другой язык

1. Завести модуль `analyzers/<lang>/` с `go.mod` (или отдельный репозиторий).
2. Реализовать тот же контракт: вход `SGATE_REPO`/`SGATE_OUT`, выход SARIF,
   прогресс `*-scanned: <файл>`.
3. Добавить запись в `core/analyzers.yaml` с `languages: [<lang>]`.
4. Добавить фикстуры и тест — как в `analyzers/ast/internal/rules/rules_test.go`.

Ядро при этом не меняется: `core/internal/analyzer` уже умеет `command` и
`docker`, а `sarif` — читать результат.

## Текущие модули

| Модуль | Язык | Правила |
|---|---|---|
| `ast` | Go | `sgate-ast-broker-entity-subject` (entity из payload без сверки с subject), `sgate-ast-identity-param` (subject_org/snapshot_id из словаря) |
| `taint` | Go | `sgate-taint-sql`, `sgate-taint-command`, `sgate-taint-file`, `sgate-taint-ssrf` — межпакетный taint «источник → сток» |
| `ssa` | Go | те же четыре правила — SSA-проход с графом вызовов RTA: находит поток через func-значения в структурах и интерфейсы, которые AST-модуль не разрешает |
| `astpy` | Python | `sgate-py-route-without-auth` (маршрут без проверки auth/прав), `sgate-py-trusted-identity-header` (X-User-* без проверки токена) |

Правила `ast` дополняют semgrep, а не заменяют: они требуют связей внутри
функции (декодирование сообщения → использование поля) и AST-обхода, которые
регулярками не выражаются.
