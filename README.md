# Nazz Core

A general-purpose Rust library for building AI agent runtimes.
Provides reusable execution contracts, storage traits, tools, and recovery.
Applications supply their own storage, integrations, and business logic.

Runtime telemetry uses `agent-model`, `agent-provider`, and `agent-stop` prefixes.

## Crates

| Crate | Purpose |
| --- | --- |
| [nazz-core](crates/nazz-core/src/lib.rs) | Identity, scope, grants, and execution context. |
| [nazz-storage](crates/nazz-storage/src/lib.rs) | Storage, journal, and dispatch traits. |
| [nazz-runtime](crates/nazz-runtime/src/lib.rs) | Rig execution, tools, checkpoints, and recovery. |
| [nazz-sandbox](crates/nazz-sandbox/src/lib.rs) | OS sandbox support for server hosts. |

Core contains no database driver, schema, or migrations. Hosts implement the
storage traits and [WorkerHost](crates/nazz-runtime/src/worker.rs), then provide
tools, policies, provider access, and budget management.
Use the [conformance suite](crates/nazz-storage/src/conformance.rs) to check
host storage adapters.

## Local integration

Replace `/path/to/nazz-core` with your local checkout:

```toml
[dependencies]
nazz-core = { path = "/path/to/nazz-core/crates/nazz-core" }
nazz-storage = { path = "/path/to/nazz-core/crates/nazz-storage" }
nazz-runtime = { path = "/path/to/nazz-core/crates/nazz-runtime" }
```

Package names use the `nazz-` prefix; Rust imports use `nazz_core`,
`nazz_storage`, `nazz_runtime`, and `nazz_sandbox`.

## Development

See [Cargo.toml](Cargo.toml) for the minimum Rust version. Run from the repo root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --lib
```

## CI and platform support

[GitHub Actions](.github/workflows/ci.yml) checks formatting, Clippy, builds,
unit tests, doctests, documentation, and package builds on Linux and macOS.
Seatbelt integration tests run on macOS. Linux sandbox integration tests require
a [suitably configured host](crates/nazz-sandbox/src/linux.rs).
Windows desktop execution requires a separate host runner.

## Releases

Use Conventional Commits (`feat:`, `fix:`, `feat!:`). After CI passes on `main`,
[release-plz](release-plz.toml) opens or updates one Release PR with versions and
changelogs. Review and merge it to release. Tags are per crate, for example
`nazz-core-v0.1.0`; the workspace shares one version.

The workflow explicitly starts CI for bot Release PRs.
No extra GitHub token is needed. Repository Actions settings must allow creating
pull requests. A manual run of [Release-plz](.github/workflows/release.yml) retries
release processing on the default branch.

Publication setup:

1. Set workspace `publish = ["crates-io"]`,
   and set `git_only = false` in `release-plz.toml`.
2. Set `CARGO_REGISTRY_TOKEN` for the first publication. Later, configure
   [trusted publishing](https://crates.io/docs/trusted-publishing) for each crate:
   repo `open-ai-sdk/nazz-core`, workflow `release.yml`, environment `crates-io`.
   Remove the token secret when switching to OIDC.
3. Protect `nazz-*-v*` tags and set repository variable
   `CRATES_IO_PUBLISH_ENABLED=true`, then merge the Release PR.

Until then, Release PRs and CI work without publishing crates, tags or releases.

## License

[Apache-2.0](LICENSE). Dependencies retain their original licenses.
