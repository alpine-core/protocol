# ALPINE Documentation Policy

ALPINE treats docs as more than help text—they are the API contract. Every public entry point across Rust, TypeScript/JavaScript, C, C++, and Python MUST document:

1. **What it does** (not just signatures) – describe behavioral guarantees, performance assumptions, and observable side effects.
2. **What it forbids** – undefined behavior or unsupported usage must be spelled out so consumers know when to guard.
3. **What can change** – use `#[deprecated]`, `@deprecated`, or Doxygen/PEP warnings when APIs evolve, and keep compatibility notes close to the declaration.

Language-specific rules:

- **Rust**: enable `#![deny(missing_docs)]`, use `///`/`//!` everywhere, add `# Errors`, `# Guarantees`, `# Examples`, annotate extensible enums/structs with `#[non_exhaustive]`, and use `#[must_use]` for values that cannot be ignored. Prefer Rust docs as canonical when terminology is ambiguous.
- **TypeScript/JavaScript**: write full JSDoc on exported APIs, describe runtime behavior, use `@deprecated` with migration guidance, and embed usage snippets.
- **C/C++**: document every header symbol with Doxygen-style comments, clearly mention ownership, threading, and safety guarantees, and mark deprecated symbols with compatibility notes; headers are the canonical contract.
- **Python**: use PEP 257 docstrings, call out side effects/errors/performance expectations, and emit warning strings when marking APIs deprecated.

Terminology (profiles, keyframes, delta frames, deadlines, `config_id`, etc.) must stay consistent across languages; cross-reference the Rust docs when there is doubt.

Documentation quality is part of ALPINE’s stability guarantee. Treat it as code: review, update, and test it along with every API change.
