# Release Process

ALPINE now has two independent release flows:

1. **Protocol** (`protocol-publish` workflow) – publishes `protocol/*` artifacts: Rust crate (`alpine-protocol-rs`), TypeScript protocol helpers (`@alpine-core/protocol`), Python helpers (`alnp`), and the C/C++ SDK headers/libraries.
2. **SDK** (`sdk-publish` workflow) – publishes the SDK crates/packages (`sdk/rust` today, others in future) that depend strictly on the published protocol layer.

Each release cycle follows this checklist:

1. **Prepare the protocol layer**
   - Run `cargo test --manifest-path protocol/rust/alpine-protocol-rs/Cargo.toml`.
   - Run `scripts/build_c.sh` (packages `libalpine.a`, `protocol/c`, and C++ headers).
   - Run `scripts/build_embedded_cpp.sh` to validate the `ALPINE_EMBEDDED` flags.
   - Run `scripts/build_ts.sh` and `scripts/build_python.sh` to produce the binding-only bundles (`@alpine-core/protocol`, `alnp`).

2. **Tag the protocol release**
   - Create a tag such as `v2.0.21` and push it to trigger `protocol-publish`.
   - The workflow tests, packages, and publishes every protocol artifact to crates.io, npm, PyPI, and GitHub Packages.

3. **Publish the SDK**
   - Once `protocol-publish` succeeds for the tag, `sdk-publish` runs for the Rust SDK only (currently `sdk/rust/alpine-protocol-sdk`).
   - TypeScript and Python SDK runtimes are archived; only Rust SDK artifacts are published in this phase.

Tokens to set:

- `CARGO_REGISTRY_TOKEN` (for crates.io/github)
- `NPM_TOKEN` (for npm/PNPM)
- `PYPI_API_TOKEN` (for PyPI/GitHub Package upload via `twine`)
- `GITHUB_TOKEN` (for uploading artifacts or releasing)

Always run the protocol checklist before tagging so both workflows operate on reproducible artifacts. Whenever a workflow fails, fix the issue locally and rerun the same commands before re-tagging.
