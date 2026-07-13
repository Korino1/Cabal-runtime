# Cabal Runtime

Cabal Runtime moves deterministic, context-heavy repository mechanics behind
standard Codex CLI hooks. The model keeps using ordinary commands. For exact
supported forms, the plugin executes or projects the operation natively and
returns a bounded semantic result instead of raw logs, patch bodies, repeated
file contents, repository bookkeeping, or an unnecessarily large file list.

No Codex fork is used. The model does not call a Cabal MCP tool, load a Cabal
skill, or perform an extra workflow step.

## How Context Noise Is Removed

The installed plugin uses standard `PreToolUse`, `PostToolUse`, `SessionStart`,
`PostCompact`, and `Stop` hooks.

1. Codex requests an ordinary supported command.
2. `PreToolUse` recognizes only a frozen exact grammar and uses
   `updatedInput` to route it to `cabal-runtime-hook`.
3. The Rust runtime keeps raw data and private indexes outside model context.
4. The command result contains only bounded decision-relevant fields, explicit
   omissions, and completeness status.
5. Unsupported commands receive no Cabal rewrite and retain normal Codex
   behavior.

This is transparent for the supported hook paths, not universal interception.
Cabal does not claim control over unsupported tools, arbitrary shell syntax,
all `unified_exec` paths, or MCP-side mutations.

## Implemented Modules

### Cargo Gateway

Simple `cargo build`, `cargo check`, `cargo clippy`, and `cargo test` commands
run through the native gateway. Full compiler and test streams stay in local
ignored artifacts. The model receives verdicts, error codes, actionable
diagnostics, source locations, and test summaries without build progress noise.

### Artifact and Log Gateway

Exact simple reads of `*.junit.xml`, `*.sarif`, `*.sarif.json`,
`*.nextest.log`, and `*.log`, plus simple `cargo nextest run` commands, are
normalized. JUnit captured output, repetitive lines, and raw report structure
stay local. Malformed structured reports never become a false success.

### Git Delta Gateway

Exactly `git status`, `git diff`, `git diff --cached`, and a bounded
`git show <revision>` are projected into changed paths, statuses,
classifications, counts, and hunk ranges. Patch bodies remain under the Git
service directory. Flags, pathspecs, revision ranges, redirection, and composed
shell commands are left unchanged.

### File Read Delta Cache

Exact bounded UTF-8 reads through `cat`, `Get-Content`, and a narrow `sed -n`
form are versioned by content hash. A repeated covered read of unchanged bytes
returns a small `unchanged` receipt. A changed file returns current requested
content plus bounded changed-line ranges. Binary, oversized, out-of-workspace,
or unsupported reads remain under normal Codex execution.

### Completion Gate

The opt-in `.cabal/completion/contract.json` is checked by the standard `Stop`
hook. An absent contract is silent. A satisfied contract adds no continuation.
Missing, stale, failed, malformed, or unavailable evidence produces one bounded
continuation containing safe criterion IDs or a generic status. Supported
criteria include Cargo command receipts, file existence/absence, and exact file
SHA-256.

### Change Policy Guard

The opt-in `.cabal/policy/change_policy.json` checks canonical `apply_patch`
and bounded simple Bash mutations before execution. It covers declared path
classes, workspace and existing-symlink containment, patch limits, exact
command rules, and built-in destructive forms. Allow is silent. Deny uses the
native `permissionDecision: "deny"` wire with one bounded code. Unsupported
grammar receives no policy decision.

### Repository Map

M-009 maintains `cabal.repository_map.v1` privately under the repository Git
service directory. It records:

- normalized file facts, SHA-256 versions, classifications, and explicit parse
  status;
- Cargo workspace packages, targets, and direct package dependency edges from
  `cargo metadata`;
- Rust modules, definitions, public/restricted visibility, imports, syntactic
  references, qualified impl/trait methods, tests, and test-to-symbol
  references from the `syn` AST;
- hard omission counters and complete/bounded/Cargo-unavailable state.

The index is refreshed silently on `SessionStart`, after supported edit tools,
and before a broad inventory rewrite when the current map predicts a smaller
projection. Unchanged files reuse parsed
facts; changed, added, and deleted files invalidate the corresponding facts.
The runtime excludes `.git`, does not follow symlinks, rejects state outside the
Git service directory, and atomically persists a deterministic bounded index.

For exactly `rg --files` and `rg --files .`, `PreToolUse` may return a bounded
`cabal.repository_inventory.v1` instead of the full list. The rewrite occurs
only when the projection is smaller than the estimated native result. Small
repositories therefore pass through unchanged rather than receiving more
context. Unsupported arguments, hidden-file flags, pipes, redirects, and
compound commands are never rewritten by this module.

In a local 2,003-file fixture, the native file list was 118,038 UTF-8 bytes and
the bounded inventory was 15,990 bytes, an 86.45% reduction. This fixture is a
regression measurement, not a universal performance claim. The projection
reported 256 retained paths and 1,747 omitted paths explicitly.

The full symbol/reference map is currently private infrastructure. Task-intent
retrieval and model-facing relevant code spans belong to the next independent
module; this release does not claim that capability.

### Supporting Normalizers

- `cabal-observe`: Cargo/rustc JSON and textual test normalization.
- `cabal-delta`: captured unified Git diff normalization.
- `cabal-log`: JUnit XML, SARIF 2.1.0, nextest, and generic log normalization.
- `cabal-repository-map`: deterministic repository and Rust syntax facts.

## Requirements

- Rust nightly, edition 2024
- Windows 11 or Linux
- No `unsafe` code in the Cabal Runtime workspace
- Standard Codex CLI with plugin and hook support

## Install In Codex CLI

```powershell
cargo +nightly install --path crates/cabal-runtime-hook --force
codex plugin marketplace add .
codex plugin add cabal-runtime@cabal-runtime-local
```

Review and trust the installed hook through `/hooks` before ordinary use. The
`--dangerously-bypass-hook-trust` option is reserved for controlled validation
and is not part of normal operation.

## Validate

```powershell
cargo +nightly fmt --all -- --check
cargo +nightly test --workspace --all-targets
cargo +nightly clippy --workspace --all-targets -- -D warnings
```

CI runs the same workspace tests on Windows and Ubuntu. Repository-map tests
cover deterministic bytes, known symbols/imports/references/tests, qualified
methods, incremental reuse/change/delete, Cargo refresh, malformed and
oversized sources, projection leakage, bounds, corrupt indexes, Git
containment, symlink omission, exact rewrites, near misses, and the
context-effectiveness gate.

## License

Dual-licensed under MIT or Apache-2.0.

---

# Cabal Runtime: описание на русском

Cabal Runtime переносит детерминированную и объёмную техническую работу за
пределы рабочего контекста модели через штатные hooks стандартного Codex CLI.
Модель продолжает использовать обычные команды. Для точно поддерживаемых форм
плагин нативно выполняет или проецирует операцию и возвращает ограниченный
семантический результат вместо сырых логов, тел patch, повторного содержимого
файлов, служебных данных runtime или чрезмерно большого списка файлов.

Fork Codex не используется. Модель не вызывает отдельный MCP-инструмент Cabal,
не загружает skill Cabal и не выполняет дополнительных шагов.

## Как плагин устраняет контекстный мусор

1. Codex запрашивает обычную поддерживаемую команду.
2. `PreToolUse` распознаёт только зафиксированную точную грамматику и через
   `updatedInput` незаметно направляет вызов в `cabal-runtime-hook`.
3. Сырые данные, хеши, полная карта и служебные пути остаются локально вне
   контекста модели.
4. Модель получает только ограниченные значимые поля, явное число пропусков и
   статус полноты.
5. Неподдерживаемая команда не изменяется и исполняется штатным Codex.

Прозрачность действует только на перечисленных путях hook API. Проект не
заявляет полный перехват произвольного shell, всех вариантов `unified_exec`,
MCP-мутаций или неизвестных инструментов.

## Реализованные модули

### Cargo Gateway

Простые `cargo build`, `cargo check`, `cargo clippy` и `cargo test` выполняются
через нативный gateway. Полный поток компилятора и тестов остаётся в локальных
игнорируемых артефактах. Модель получает итог, коды ошибок, важные диагностики,
координаты и сводку тестов без шума процесса сборки.

### Artifact and Log Gateway

Точные простые чтения JUnit, SARIF, nextest и обычных `*.log`, а также простые
`cargo nextest run`, нормализуются. Захваченный тестовый вывод, повторяющиеся
строки и сырая структура отчёта не попадают модели. Повреждённый
структурированный отчёт никогда не объявляется успешным.

### Git Delta Gateway

Только `git status`, `git diff`, `git diff --cached` и ограниченный
`git show <revision>` преобразуются в пути, статусы, классификации, счётчики и
диапазоны hunks. Тела patch остаются в служебном каталоге Git. Флаги, pathspec,
диапазоны revisions, перенаправление и составные команды не перехватываются.

### File Read Delta Cache

Точные ограниченные UTF-8 чтения через `cat`, `Get-Content` и узкую форму
`sed -n` версионируются по хешу содержимого. Повторное чтение неизменённых уже
покрытых байтов возвращает короткий статус `unchanged`. После изменения
возвращается актуальный запрошенный фрагмент и ограниченные диапазоны
изменённых строк. Неподдерживаемые чтения выполняются штатно.

### Completion Gate

Опциональный `.cabal/completion/contract.json` проверяется hook `Stop`.
Отсутствующий или выполненный контракт не добавляет модели действий. При
отсутствующем, устаревшем, неуспешном или повреждённом доказательстве Codex
получает одно короткое продолжение с безопасными ID критериев или общим
статусом.

### Change Policy Guard

Опциональный `.cabal/policy/change_policy.json` проверяет канонический
`apply_patch` и ограниченные простые Bash-мутации до исполнения. Разрешение
ничего не выводит. Запрет использует штатный `permissionDecision: "deny"` с
одним коротким кодом. Неподдерживаемая грамматика не получает решения Cabal.

### Repository Map

M-009 скрыто ведёт `cabal.repository_map.v1` в служебном каталоге Git. Карта
содержит версии и классификации файлов, Cargo packages/targets/dependencies, а
также извлечённые parser-ом `syn` Rust-модули, определения, visibility, imports,
синтаксические references, квалифицированные impl/trait methods и тесты.
Повреждённые и слишком большие исходники, превышение bounds, ошибки Cargo и
другие пропуски всегда отражаются явно; неполный индекс не выдаётся за полный.

Карта обновляется без передачи содержимого модели на `SessionStart`, после
поддерживаемых операций редактирования и перед rewrite инвентаризации, если
текущая карта прогнозирует меньшую проекцию. Неизменённые файлы повторно используют разобранные факты;
изменённые, добавленные и удалённые файлы инвалидируют соответствующие данные.
`.git` исключён, symlinks не обходятся, а состояние вне служебного каталога Git
отклоняется.

Для точных `rg --files` и `rg --files .` плагин может незаметно вернуть
ограниченный `cabal.repository_inventory.v1`. Rewrite выполняется только если
проекция меньше ожидаемого штатного списка. Поэтому на маленьком репозитории
плагин не увеличивает контекст, а оставляет команду без изменений. Флаги,
аргументы, pipes, redirects и составные команды модуль не перехватывает.

В локальном fixture на 2 003 файлах список занимал 118 038 байт UTF-8, а
проекция 15 990 байт: сокращение 86,45%. Это регрессионное измерение, а не
универсальная гарантия производительности. Проекция явно сообщила 256
сохранённых и 1 747 пропущенных пути.

Полная карта символов и references пока остаётся внутренней инфраструктурой.
Выбор релевантных фрагментов по намерению задачи относится к следующему
независимому модулю; этот релиз не заявляет такую возможность.

## Установка и проверка

```powershell
cargo +nightly install --path crates/cabal-runtime-hook --force
codex plugin marketplace add .
codex plugin add cabal-runtime@cabal-runtime-local

cargo +nightly fmt --all -- --check
cargo +nightly test --workspace --all-targets
cargo +nightly clippy --workspace --all-targets -- -D warnings
```

После установки новый точный hash hook необходимо один раз проверить и
доверить через `/hooks`. Опция `--dangerously-bypass-hook-trust` предназначена
только для контролируемых тестов и не требуется при обычной работе.

Лицензия: MIT или Apache-2.0.
