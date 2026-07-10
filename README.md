# Cabal Runtime

Cabal Runtime is a Rust workspace for moving deterministic repository mechanics out of a model's working context.

The target product is an invisible runtime layer: models should receive only the semantic result needed for a decision, not raw compiler logs, test output, unified diffs, hashes, artifact storage details, or orchestration mechanics.

## Current Components

### `cabal-observe`

Normalizes saved build and test output into `ObservationPack` JSON.

- Parses Cargo/rustc JSON diagnostics.
- Parses textual Cargo test failures and panics.
- Persists raw input under a SHA-256-addressed local artifact path.
- Returns verdict, actionable diagnostics, test summary, omission accounting, and an artifact identity.

### `cabal-delta`

Normalizes an already captured unified Git diff into `DeltaPack` JSON.

- Does not execute Git commands.
- Retains file status, old/new paths, hunk ranges, addition/deletion counts, rename and binary markers.
- Rejects unsupported quoted Git paths instead of guessing.
- Persists raw input under a SHA-256-addressed local artifact path.

Each component is an independent crate. Neither invokes the other, performs policy decisions, retrieves repository context, or exposes a model-facing tool.

## Requirements

- Rust nightly
- Rust edition 2024
- Windows 11 is the primary local development platform
- Linux is a required portability target

The codebase currently contains no `unsafe` code.

## Build and Test

```powershell
cargo +nightly fmt --check
cargo +nightly test --workspace
cargo +nightly clippy --workspace --all-targets -- -D warnings
cargo +nightly check --workspace --all-targets --target x86_64-unknown-linux-gnu
```

## Development Harnesses

Normalize saved Cargo JSON:

```powershell
cargo +nightly run -p cabal-observe -- normalize `
  --kind cargo-json `
  --input tests/fixtures/cargo-error.jsonl
```

Normalize a saved unified diff:

```powershell
cargo +nightly run -p cabal-delta -- normalize `
  --input crates/cabal-delta/tests/fixtures/noisy-change.diff
```

Raw inputs are written below `.cabal/artifacts/` by default. This is local runtime state and is intentionally not tracked by Git.

## Status

The deterministic normalization modules are locally validated on Windows and cross-compile for `x86_64-unknown-linux-gnu`. Actual Linux test execution has not yet been run in this environment.

The complete invisible Codex runtime, including hidden lifecycle interception, task contracts, evidence gates, contextual retrieval, and agent-loop virtualization, is not implemented yet. The current commands are development harnesses, not model-facing product tools.

## License

Dual-licensed under MIT or Apache-2.0.
