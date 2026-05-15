# Architecture

npm-gate is split into small modules that communicate through plain typed data.

- `cli/` parses commands and maps npm-like verbs to engine calls.
- `core/` defines decisions, scoring, shared types, and the orchestration engine.
- `config/` loads and validates policy from defaults, config files, and environment overrides.
- `registry/` fetches npm registry metadata and tarballs with cache, timeout, safe unpacking, and integrity support.
- `intelligence/` adapts external advisory sources such as OSV into the internal advisory shape.
- `analyzers/` converts manifests, artifact diffs, dependency closures, metadata, lockfiles, local sources, tarball filenames and bounded content samples, advisories, package names, provenance metadata, credential exposure categories, frontend runtime samples, emergency denylists, and GitHub workflows into risk signals.
- `policy/` applies package allowlists, narrow lifecycle script allowlists, exceptions, thresholds, runtime mode, and policy mode to produce decisions.
- `wrappers/` classifies npm command arguments and delegates to npm only after policy allows it.
- `reporting/` emits console, JSON, and basic SARIF output.
- `sandbox/` documents non-executing future sandbox plans.

The engine never executes package code. Static analysis happens before npm or pnpm delegation, and delegation can be disabled with `--dry-run`, `--no-execute`, or CI policy. Local directories, local tarballs, configured-registry direct tarballs, production-profile registry package tarballs, and production-profile transitive registry dependencies are inspected before install decisions. Git and GitHub sources remain policy-gated without cloning.

`npm-gate ci` adds project-level checks for lockfile host/integrity risks and GitHub Actions release risks. `npm-gate emergency` adds local denylist lockfile rescans plus incident-response guidance. These findings use the same policy engine as package findings, so SARIF, JSON, console output, exceptions, and exit codes stay consistent.

## Policy Flow

1. Resolve package candidates without running lifecycle scripts.
2. Inspect manifests, lockfiles, dependency closures, registry metadata, current and previous tarball entries, configured source tags/commits, and bounded content samples.
3. Convert evidence into typed risk signals with categories and matched signal IDs.
4. Apply script-hash allowlists only to exact lifecycle script matches.
5. Apply package allowlists only to package approval or new-package-name policy, not lifecycle execution.
6. Apply exceptions where policy permits.
7. Emit additive JSON fields while preserving existing fields.

## Analyzer Notes

- Lifecycle analysis is manifest-only and never executes scripts.
- Artifact diffing reports script changes, binary or suspicious file additions, size deltas, repository metadata changes, and tarball/source mismatch metadata when available.
- Dependency delta analysis reports newly introduced direct and transitive packages plus dependency paths from package-lock paths or registry closure traversal.
- Provenance validation checks configured expectations but cannot authorize risky code by itself.
- Source verification is disabled by default and uses a small GitHub verifier behind an injectable interface so tests can stay offline.
- Workflow scanning uses YAML parsing and static command inspection. It detects unsafe cache/OIDC, `pull_request_target`, `workflow_run`, unpinned action, self-hosted runner, and publish-after-risky-install patterns.
- Credential exposure analysis reports categories only. It never includes secret values.
- Frontend runtime analysis is bounded static sample scanning, not browser execution.
- Emergency analysis consumes only local config and does not contact a live incident feed.

## Reporting Notes

JSON output remains additive. SARIF output preserves its existing structure and adds finding properties for decision, severity, risk category, policy mode, matched signals, evidence summary, recommended fix, dependency path, allowlist state, kill chain, overrideability, and suppression state.
