# Architecture

npm-gate is split into small modules that communicate through plain typed data.

- `cli/` parses commands and maps npm-like verbs to engine calls.
- `core/` defines decisions, scoring, shared types, and the orchestration engine.
- `config/` loads and validates policy from defaults, config files, and environment overrides.
- `registry/` fetches npm registry metadata and tarballs with cache, timeout, safe unpacking, and integrity support.
- `intelligence/` adapts external advisory sources such as OSV into the internal advisory shape.
- `analyzers/` converts manifests, dependency closures, metadata, lockfiles, local sources, tarball filenames and bounded content samples, advisories, package names, and GitHub workflows into risk signals.
- `policy/` applies allowlists, exceptions, thresholds, and runtime mode to produce decisions.
- `wrappers/` classifies npm command arguments and delegates to npm only after policy allows it.
- `reporting/` emits console, JSON, and basic SARIF output.
- `sandbox/` documents non-executing future sandbox plans.

The engine never executes package code. Static analysis happens before npm or pnpm delegation, and delegation can be disabled with `--dry-run`, `--no-execute`, or CI policy. Local directories, local tarballs, configured-registry direct tarballs, production-profile registry package tarballs, and production-profile transitive registry dependencies are inspected before install decisions. Git and GitHub sources remain policy-gated without cloning.

`npm-gate ci` adds project-level checks for lockfile host/integrity risks and GitHub Actions release risks. These findings use the same policy engine as package findings, so SARIF, JSON, console output, exceptions, and exit codes stay consistent.
