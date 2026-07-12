# Cabal Runtime

Cabal Runtime moves deterministic repository mechanics out of a model's working context. Models receive the bounded semantic result needed for a decision instead of raw compiler output, test logs, report noise, hashes, artifact paths, or runtime bookkeeping.

## Native Codex Integration

The bundled `cabal-runtime` plugin uses the standard Codex `PreToolUse` hook. It transparently rewrites only recognized simple Bash tool calls before execution. The model does not call a Cabal tool, load a Cabal skill, or perform an extra workflow step.

The native Rust gateway:

- executes recognized commands directly without a shell;
- stores complete stdout, stderr, and report bytes under ignored `.cabal/artifacts/`;
- returns a bounded JSON projection with verdicts, counts, actionable diagnostics, and source locations;
- excludes progress noise, captured output, hashes, artifact paths, and Cabal bookkeeping from the model-facing result;
- leaves unrecognized or composed shell commands unchanged.

This runs in the standard Codex CLI without a fork. Transparency applies to the supported hook paths listed below; Cabal does not claim interception of every possible Codex tool or shell expression.

## Implemented Modules

### Cargo Gateway

Simple `cargo build`, `cargo check`, `cargo clippy`, and `cargo test` calls are redirected to the native gateway. Compiler and test output is normalized while error codes, locations, verdicts, and failure summaries are retained.

### Artifact and Log Gateway

Simple report reads are redirected when their file name identifies a supported format:

- `Get-Content report.junit.xml` or `cat report.junit.xml`: JUnit XML;
- `Get-Content report.sarif` or `cat report.sarif.json`: SARIF 2.1.0;
- `Get-Content report.nextest.log` or `cat report.nextest.log`: nextest text;
- `Get-Content report.log` or `cat report.log`: bounded generic diagnostics.

Simple `cargo nextest run ...` calls are also recognized. JUnit `system-out`/`system-err`, repetitive log lines, and non-actionable report structure remain in the local raw artifact. The projection preserves suite/test identity, pass/fail/skip/error counts, rule IDs, messages, primary locations, and related SARIF locations. Malformed structured input produces `normalization_failed`; it never produces a false success verdict.

### Git Delta Gateway

The gateway transparently rewrites exactly four read-only command forms:

- `git status`;
- `git diff`;
- `git diff --cached`;
- `git show <revision>`, where the revision is a single bounded commit expression.

Git runs directly without a shell, external diff drivers, or textconv. The model receives changed paths, staged/unstaged/untracked state, add/modify/delete/rename markers, file classification, binary markers, additions/deletions, and bounded hunk ranges. Patch bodies are retained only under the repository's Git service directory and are not returned to the model. Requests and artifacts do not change the worktree, index, refs, or visible Git status.

The gateway rejects flags, pathspecs, revision ranges, redirection, and composed shell commands. This module does not claim symbol, API, or behavioral interpretation.

### File Read Delta Cache

The gateway recognizes four exact bounded UTF-8 text reads: `cat <path>`, `Get-Content <path>`, `Get-Content -Raw <path>`, and `sed -n '<start>,<end>p' <path>`. A first read returns the exact requested content. A repeated covered read of unchanged content returns only a small `unchanged` receipt. When the file changes, the gateway returns the exact current requested content plus bounded changed-line ranges.

Observations are scoped to the Codex session and invalidated by the standard `SessionStart` and `PostCompact` lifecycle hooks. Cabal hashes the bytes on every intercepted read, so same-size rewrites and restored timestamps cannot produce a false unchanged result. Cache hashes, snapshot paths, locks, and other bookkeeping never enter model-facing output.

Full-file reads are limited to 256 KiB. Line reads are limited to 400 lines and 64 KiB, paths to 4096 bytes, and changed ranges to 64 entries. Binary data, invalid UTF-8, files outside the workspace, oversized requests, flags, wildcards, and composed shell expressions are left untouched for normal Codex execution.

### Supporting Normalizers

- `cabal-observe` normalizes Cargo/rustc JSON and textual test output.
- `cabal-delta` normalizes an already captured unified Git diff.
- `cabal-log` independently normalizes JUnit XML, SARIF 2.1.0, nextest text, and generic logs.

## Requirements

- Rust nightly
- Rust edition 2024
- Windows 11 or Linux
- No `unsafe` code

## Install in Codex CLI

From the repository root:

```powershell
cargo +nightly install --path crates/cabal-runtime-hook --force
codex plugin marketplace add .
codex plugin add cabal-runtime@cabal-runtime-local
```

Review and trust the installed hook through `/hooks` before ordinary Codex use. The `--dangerously-bypass-hook-trust` flag is reserved for controlled validation and is not required for normal operation after trust is recorded.

## Validate

```powershell
cargo +nightly fmt --all -- --check
cargo +nightly test --workspace --all-targets
cargo +nightly clippy --workspace --all-targets -- -D warnings
```

CI runs the test suite on Windows and Linux. Regression tests verify JUnit context reduction and prove that all Git gateway queries leave HEAD, index, and visible status unchanged while patch bodies remain outside model-facing output.

File-cache regression tests cover repeated and newly requested ranges, BOM and Unicode, CRLF and missing final newlines, same-metadata rewrites, rapid changes, concurrent readers, session changes, compact invalidation, rename/delete behavior, path containment, invalid UTF-8, and size limits.

## License

Dual-licensed under MIT or Apache-2.0.

## Описание на русском

### Кэш дельт чтения файлов

Gateway распознаёт четыре точные ограниченные формы чтения UTF-8 текста: `cat <path>`, `Get-Content <path>`, `Get-Content -Raw <path>` и `sed -n '<start>,<end>p' <path>`. Первое чтение возвращает точное запрошенное содержимое. Повторное чтение уже просмотренного и неизменённого диапазона возвращает только короткую квитанцию `unchanged`. После изменения файла модель получает точное текущее содержимое запрошенного диапазона и ограниченный список изменённых диапазонов строк.

Наблюдения изолированы по сессии Codex и сбрасываются штатными hooks `SessionStart` и `PostCompact`. При каждом перехваченном чтении Cabal заново хеширует байты, поэтому замена файла с тем же размером и восстановленным временем изменения не создаёт ложный результат `unchanged`. Хеши, пути снимков, блокировки и служебное состояние не передаются модели.

Полное чтение ограничено 256 КиБ. Диапазон ограничен 400 строками и 64 КиБ, путь — 4096 байтами, список изменений — 64 элементами. Бинарные данные, невалидный UTF-8, файлы вне рабочей области, превышение лимитов, флаги, wildcard и составные shell-выражения плагин не перехватывает: их штатно исполняет Codex.

Cabal Runtime переносит детерминированную техническую обработку за пределы рабочего контекста модели. Вместо сырых логов компиляции и тестов, шума отчётов, хешей, путей артефактов и внутренних записей модель получает ограниченный семантический результат, необходимый для следующего решения.

Плагин `cabal-runtime` использует штатный hook `PreToolUse` стандартного Codex CLI. До выполнения он незаметно перенаправляет только распознанные простые вызовы Bash. Модель не вызывает инструмент Cabal, не загружает skill Cabal и не выполняет дополнительных шагов. Fork Codex не используется.

Реализованный Cargo Gateway обрабатывает простые команды `cargo build`, `cargo check`, `cargo clippy` и `cargo test`. Полные stdout и stderr сохраняются локально в игнорируемом каталоге `.cabal/artifacts/`, а в контекст модели возвращаются итог, коды ошибок, важные диагностики, координаты в исходниках и сводка тестов.

Реализованный Artifact and Log Gateway перехватывает простое чтение файлов `*.junit.xml`, `*.sarif`, `*.sarif.json`, `*.nextest.log` и `*.log`, а также простые вызовы `cargo nextest run`. Он поддерживает JUnit XML, SARIF 2.1.0, текст nextest и ограниченную обработку обычных логов. В контексте сохраняются идентификаторы suite/test, счётчики pass/fail/skip/error, rule ID, сообщения и координаты. `system-out`, `system-err`, повторяющиеся строки и служебная структура остаются только в локальном сыром артефакте. Повреждённый структурированный отчёт получает статус `normalization_failed` и не может быть объявлен успешным.

Реализованный Git Delta Gateway незаметно перехватывает только четыре read-only формы: `git status`, `git diff`, `git diff --cached` и `git show <revision>` для одного ограниченного выражения commit. Git запускается напрямую без shell, внешних diff-драйверов и textconv. Модель получает пути, staged/unstaged/untracked состояние, тип изменения, классификацию файла, binary-маркеры, счётчики additions/deletions и ограниченные диапазоны хунков. Тело patch остаётся только в служебном каталоге Git и не возвращается модели. Gateway не изменяет worktree, index, refs или видимый Git status.

Флаги, pathspec, диапазоны revisions, перенаправление и составные shell-команды не перехватываются. Модуль не заявляет анализ символов, API или поведения: это отдельные будущие уровни.

Прозрачность действует для перечисленных поддерживаемых путей hook API. Неизвестные и составные shell-команды не изменяются; проект не заявляет перехват всех возможных инструментов Codex. Каждый нормализатор является отдельным Rust-модулем, поэтому модули выполняют свои задачи независимо и объединяются только в границе нативного gateway.
