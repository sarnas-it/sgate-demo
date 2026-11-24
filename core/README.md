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

Сейчас в конфиге Semgrep (все языки), gosec (Go, если есть `go.mod`), Bandit (Python, JSON) и Psalm (PHP, SARIF + taint). Образы закреплены по `@sha256`; каталог — `analyzers.lock`, проверка — `scripts/check-pins.sh`.
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
- `exclude` — fixtures и testdata не блокируют сам SGATE;
- diff-only (`--base/--head`) и кэш по коммиту (`.sgate-cache/`);
- определение языков по расширениям;
- оркестратор с таймаутами; анализаторы запускаются параллельно;
- нормализация SARIF в единую модель (severity по CVSS и уровню);
- политика block/warn;
- baseline/fingerprint: старые находки не блокируют новые PR;
- тесты на конфиг, языки, SARIF, политику и запуск адаптера.

## Baseline

Принять текущие находки, чтобы они не блокировали PR:

```bash
go run ./cmd/sgate --repo .. --config analyzers.yaml \
  --write-baseline .sgate-baseline.json

go run ./cmd/sgate --repo .. --config analyzers.yaml \
  --baseline .sgate-baseline.json
```

Baseline матчится по fingerprint анализатора; если его нет — по
`analyzer + rule + file + message`. Принятые находки печатаются как `[base ]`
и не блокируют.

## Интеграционные тесты адаптеров

Нужен Docker:

```bash
SGATE_INTEGRATION=1 go test ./internal/analyzer -run 'Test(Bandit|Gosec|Psalm)Adapter' -v
```

## Дальше по бэклогу

M2: `phpstan`/`psalm`, Bandit, ESLint; каталог версий; baseline;
SARIF upload в GitHub; conformance-тесты для нового адаптера.
