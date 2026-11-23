# SGATE core — платформа SAST-анализаторов

Прототип M1: SGATE запускает сменные анализаторы и читает их SARIF. Язык — это
запись в `analyzers.yaml`, а не код SGATE.

## Быстрый старт

```bash
cd core
go test ./...
go run ./cmd/sgate --repo .. --config analyzers.yaml --list
go run ./cmd/sgate --repo .. --config analyzers.yaml --format text
```

Сейчас в конфиге Semgrep (все языки) и gosec (Go, если есть `go.mod`).
Новый язык — запись в `analyzers.yaml`, код не меняется.

## Контракт анализатора

`analyzers.yaml`:

```yaml
analyzers:
  - id: semgrep
    languages: [go, php, python, typescript]
    runtime: docker            # docker | command
    image: semgrep/semgrep:1.186.0
    workdir: /src
    command: [semgrep, scan, --config, /rules, --sarif, --output, /out/semgrep.sarif]
    mounts:
      - source: ../sast-rules
        target: /rules
        read_only: true
    output: /out/semgrep.sarif
    network: none
    timeout: 10m
```

- `languages` — какие языки покрывает; SGATE запускает анализатор только если
  язык найден в репозитории.
- `runtime: docker` — запуск в контейнере: `--network none`, non-root,
  read-only репозиторий, без docker.sock, лимит pids.
- `runtime: command` — для тестов и локальных бинарников; получает
  `SGATE_REPO` и `SGATE_OUT`.
- `output` — SARIF; для docker обязан быть внутри `/out/`.

## Что уже есть

- загрузка и валидация конфига;
- определение языков по расширениям;
- оркестратор с таймаутами; адаптеры запускаются последовательно в M1;
- нормализация SARIF в единую модель (severity по CVSS и уровню);
- политика block/warn;
- тесты на конфиг, языки, SARIF, политику и запуск адаптера.

## Интеграционный тест gosec

Нужен Docker:

```bash
SGATE_INTEGRATION=1 go test ./internal/analyzer -run TestGosecAdapter -v
```

## Дальше по бэклогу

M2: `phpstan`/`psalm`, Bandit, ESLint; каталог версий; baseline;
SARIF upload в GitHub; conformance-тесты для нового адаптера.
