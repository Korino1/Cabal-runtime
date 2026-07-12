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

CI runs the test suite on Windows and Linux. A regression test verifies that a noisy JUnit report is reduced by more than 10x while its actionable failure evidence remains available to the model.

## License

Dual-licensed under MIT or Apache-2.0.

## Описание на русском

Cabal Runtime переносит детерминированную техническую обработку за пределы рабочего контекста модели. Вместо сырых логов компиляции и тестов, шума отчётов, хешей, путей артефактов и внутренних записей модель получает ограниченный семантический результат, необходимый для следующего решения.

Плагин `cabal-runtime` использует штатный hook `PreToolUse` стандартного Codex CLI. До выполнения он незаметно перенаправляет только распознанные простые вызовы Bash. Модель не вызывает инструмент Cabal, не загружает skill Cabal и не выполняет дополнительных шагов. Fork Codex не используется.

Реализованный Cargo Gateway обрабатывает простые команды `cargo build`, `cargo check`, `cargo clippy` и `cargo test`. Полные stdout и stderr сохраняются локально в игнорируемом каталоге `.cabal/artifacts/`, а в контекст модели возвращаются итог, коды ошибок, важные диагностики, координаты в исходниках и сводка тестов.

Реализованный Artifact and Log Gateway перехватывает простое чтение файлов `*.junit.xml`, `*.sarif`, `*.sarif.json`, `*.nextest.log` и `*.log`, а также простые вызовы `cargo nextest run`. Он поддерживает JUnit XML, SARIF 2.1.0, текст nextest и ограниченную обработку обычных логов. В контексте сохраняются идентификаторы suite/test, счётчики pass/fail/skip/error, rule ID, сообщения и координаты. `system-out`, `system-err`, повторяющиеся строки и служебная структура остаются только в локальном сыром артефакте. Повреждённый структурированный отчёт получает статус `normalization_failed` и не может быть объявлен успешным.

Прозрачность действует для перечисленных поддерживаемых путей hook API. Неизвестные и составные shell-команды не изменяются; проект не заявляет перехват всех возможных инструментов Codex. Каждый нормализатор является отдельным Rust-модулем, поэтому модули выполняют свои задачи независимо и объединяются только в границе нативного gateway.
