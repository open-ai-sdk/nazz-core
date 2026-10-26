# Nazz Core

A general-purpose Rust library for building AI agent runtimes.
Provides reusable execution contracts, storage traits, tools, and recovery.
Applications supply their own storage, integrations, and business logic.

Runtime telemetry uses `agent-model`, `agent-provider`, and `agent-stop` prefixes.

## Crates

| Crate | Purpose |
| --- | --- |
| [agent-core](crates/agent-core/src/lib.rs) | Identity, scope, grants, and execution context. |
| [agent-storage](crates/agent-storage/src/lib.rs) | Storage, journal, and dispatch traits. |
| [agent-runtime](crates/agent-runtime/src/lib.rs) | Rig execution, tools, checkpoints, and recovery. |
| [agent-sandbox](crates/agent-sandbox/src/lib.rs) | OS sandbox support for server hosts. |

Core contains no database driver, schema, or migrations. Hosts implement the
storage traits and [WorkerHost](crates/agent-runtime/src/worker.rs), then provide
tools, policies, provider access, and budget management.
Use the [conformance suite](crates/agent-storage/src/conformance.rs) to check
host storage adapters.

## Local integration

Replace `/path/to/nazz-core` with your local checkout:

```toml
[dependencies]
agent-core = { path = "/path/to/nazz-core/crates/agent-core" }
agent-storage = { path = "/path/to/nazz-core/crates/agent-storage" }
agent-runtime = { path = "/path/to/nazz-core/crates/agent-runtime" }
```

Publishing is disabled. Local dependencies will move to a pinned Git revision
once the owner commits and pushes the repository.

## Development

See [Cargo.toml](Cargo.toml) for the minimum Rust version. Run from the repo root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --lib
python3 scripts/verify-core-boundary.py
```

The verifier checks [source-candidate.json](contracts/source-candidate.json).
After reviewing source changes, refresh it with `--write-candidate`.

## CI and platform support

[GitHub Actions](.github/workflows/ci.yml) checks formatting, Clippy, builds,
unit tests, doctests, documentation, and source boundaries on Linux and macOS.
Seatbelt integration tests run on macOS. Linux sandbox integration tests require
a [suitably configured host](crates/agent-sandbox/src/linux.rs).
Windows desktop execution requires a separate host runner.
