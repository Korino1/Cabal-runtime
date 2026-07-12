# Cabal Runtime

Cabal Runtime moves deterministic repository mechanics out of a model's working context. Models receive the semantic result needed for a decision instead of raw compiler logs, test output, unified diffs, hashes, artifact paths, or runtime bookkeeping.

## Native Codex Integration

The bundled `cabal-runtime` plugin uses the standard Codex `PreToolUse` hook. It transparently rewrites simple `cargo build`, `cargo check`, `cargo clippy`, and `cargo test` Bash calls before execution.

The native Rust gateway:

- runs Cargo directly without a shell;
- stores complete stdout and stderr under ignored `.cabal/artifacts/`;
- returns a bounded JSON projection containing verdicts and actionable diagnostics;
- preserves compiler error codes, locations, and test failure summaries;
- removes progress noise, raw source excerpts, hashes, artifact paths, and Cabal bookkeeping from the model-facing result.

This integration runs in the standard Codex CLI without a fork. It adds no MCP tools and no skill prompt surface, so operation does not consume model instructions or require model actions.

## Components

### `cabal-runtime-hook`

Native Codex hook runtime and Cargo context gateway.

### `cabal-observe`

Normalizes saved Cargo/rustc JSON and textual test output into `ObservationPack` JSON. Raw input is persisted locally by SHA-256 identity.

### `cabal-delta`

Normalizes an already captured unified Git diff into `DeltaPack` JSON, preserving file status, paths, hunk ranges, change counts, rename markers, and binary markers.

Each component is an independent Rust crate.

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

Review and trust the installed hook through `/hooks` before ordinary Codex use. The `--dangerously-bypass-hook-trust` flag is only for controlled validation.

## Validate

```powershell
cargo +nightly fmt --all -- --check
cargo +nightly test --workspace
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +nightly check --workspace --all-targets --target x86_64-unknown-linux-gnu
```

The native gateway has been exercised in standard Codex CLI on Windows for successful checks, compiler failures, and test suites. The workspace also cross-compiles for `x86_64-unknown-linux-gnu`.

## License

Dual-licensed under MIT or Apache-2.0.

## Описание на русском

Cabal Runtime переносит детерминированную техническую обработку за пределы рабочего контекста модели. Вместо сырых логов компиляции и тестов, полного Git diff, хешей, путей артефактов и служебных записей модель получает только краткий семантический результат, необходимый для следующего решения.

Плагин `cabal-runtime` нативно использует стандартный hook `PreToolUse` в Codex CLI. Простые вызовы `cargo build`, `cargo check`, `cargo clippy` и `cargo test` незаметно перенаправляются в Rust gateway до выполнения. Gateway запускает Cargo без shell, сохраняет полный stdout и stderr локально в игнорируемом каталоге `.cabal/artifacts/`, а модели возвращает ограниченную JSON-проекцию.

В контексте модели сохраняются итог операции, коды ошибок компилятора, важные диагностики, позиции в исходниках и сводка падений тестов. Progress-строки, сырые фрагменты исходников, хеши, пути артефактов и внутренние записи Cabal в контекст модели не передаются.

Интеграция работает в стандартном Codex CLI без fork. Она не добавляет MCP-инструменты и не использует skill-инструкции, поэтому модели не требуется знать о работе плагина или выполнять дополнительные действия.
