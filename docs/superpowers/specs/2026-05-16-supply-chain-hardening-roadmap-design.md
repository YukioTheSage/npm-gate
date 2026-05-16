# Supply Chain Hardening Roadmap Design

## Context

This repository is `npm-gate`, a defensive npm supply-chain security CLI. Current code already includes the core wrapper, policy engine, registry metadata checks, lifecycle-script detection, tarball inspection, dependency closure analysis, source and provenance metadata checks, lockfile checks, GitHub Actions workflow analysis, emergency denylist logic, SARIF and JSON reporting, and CI-mode blocking.

Recent hardening work on the current branch already covers several items from the external review:

- `npm-gate ci --release-audit` exists and enables deep transitive tarball inspection.
- Production profile requires direct tarball inspection, integrity matching, transitive dependency inspection, workflow SHA pinning, release-cache blocking, and local intelligence.
- OSV advisory querying exists behind `requiredIntelligenceSources`.
- Source verification and expected provenance rules exist behind config.
- A non-executing `--sandbox-plan` exists, but not an enforced sandbox runner.
- Documentation already states that provenance and trusted publishing are signals, not safety bypasses.

The roadmap below converts the remaining feedback into phased, spec-driven work. Each phase is independently useful and testable.

## Goals

- Fix operational bootstrap gaps that could let lifecycle scripts run before analysis.
- Extend lockfile security parity beyond `package-lock.json` to `pnpm-lock.yaml` and `yarn.lock`.
- Improve static tarball analysis for full-file text scanning and invisible Unicode payloads.
- Add explicit trusted-publishing and provenance policy semantics for high-impact packages.
- Add a cryptographic verification abstraction for npm registry signatures and Sigstore provenance attestations.
- Add optional signed incident intelligence feeds with fail-closed policy when configured as required.
- Add an enforced no-secret install mode with exact script-hash allowlisting.
- Harden the published dependency tree of `npm-gate` itself.

## Non-Goals

- Do not execute package code during analysis.
- Do not add dynamic malware detonation to the default scanner.
- Do not print secret values, token values, credential file contents, or environment variable values.
- Do not let provenance, signatures, trusted publishing, package popularity, or maintainer legitimacy bypass lifecycle, tarball, dependency, frontend runtime, workflow, or lockfile checks.
- Do not broaden lifecycle script allowlists into package-name-only rules.
- Do not make unit or integration tests depend on live npm, GitHub, OSV, or third-party feed availability.

## Phase 1: CI Bootstrap Safety And Bypass Guards

The GitHub Actions example must not install dependencies with lifecycle scripts before running `npm-gate`. Replace the unsafe example with an `--ignore-scripts` bootstrap, local build, and `node dist/index.js ci --release-audit --json` execution. Also add a CI/release guard that rejects `NPM_GATE_MODE=off` when `CI=true`, `GITHUB_ACTIONS=true`, or a release-related environment marker is present.

This phase is high priority because it closes the most practical operational bypass without large architectural changes.

## Phase 2: pnpm And Yarn Lockfile Security Parity

`analyzeLockfileSecurity()` currently performs unapproved host and baseline integrity checks only for `package-lock.json`. Extend it to parse `pnpm-lock.yaml` and Yarn classic `yarn.lock`, emitting the same stable signal IDs where possible with evidence that names the source lockfile.

Baseline support should become lockfile-family aware:

- `previousPackageLockPath` remains supported for compatibility.
- New optional baseline paths support `previousPnpmLockPath` and `previousYarnLockPath`.
- Environment variables provide equivalent support without changing existing behavior.

## Phase 3: Full Static Tarball And Invisible Unicode Scanning

Tarball content scanning currently relies on bounded samples. Keep bounded default behavior for very large files, but add a policy-controlled full-text scan path for eligible text entries. Add invisible Unicode detection across sampled and full text.

The scanner should detect code points and sequences that are commonly used for hidden-source attacks:

- bidirectional controls such as U+202A through U+202E, U+2066 through U+2069;
- zero-width characters such as U+200B, U+200C, U+200D, U+2060, U+FEFF;
- variation selector ranges U+FE00 through U+FE0F and U+E0100 through U+E01EF.

Signals should be actionable but not noisy. In strict or production contexts, invisible Unicode in executable source files should block or fail strict exit semantics.

## Phase 4: Trusted Publishing And Provenance Policy

Add policy knobs that distinguish these concepts:

- provenance present in npm metadata;
- expected provenance source fields matching configured rules;
- package is required to use trusted publishing for high-impact packages;
- package claims trusted publishing but the trust metadata cannot be verified.

Trusted publishing and provenance continue to be publish-path signals only. They cannot suppress any other risk. Missing or mismatched trusted-publishing evidence for high-impact packages should block under strict and production policy.

## Phase 5: Cryptographic Signature And Attestation Verification

Introduce a verification abstraction rather than embedding a live command directly in analyzers. The default implementation can shell out to `npm audit signatures` or use a verifier implementation when one is provided. Tests use injected verifiers with local fixtures.

The initial interface reports:

- registry signature verified;
- registry signature missing;
- registry signature present but unverified;
- provenance attestation verified;
- provenance attestation missing;
- verifier unavailable;
- verifier returned an invalid or unsupported result.

Production and release-audit flows can be configured to fail closed when verification is required and unavailable.

## Phase 6: Signed Incident Intelligence Feeds

Add optional signed incident intelligence feeds for fast-moving malicious package intelligence. The existing local advisory feed remains deterministic and built in. New feed support must require explicit config and must verify signatures before trusting feed content.

The feed layer should support:

- local signed file path;
- HTTPS endpoint only when explicitly configured;
- key identity or public key pin in config;
- cache file with signature metadata;
- fail-closed behavior when the feed is listed in `requiredIntelligenceSources`.

## Phase 7: Enforced No-Secret Install Mode

`--sandbox-plan` is informational. Add an execution mode that actually delegates package-manager installs with a scrubbed environment and safer defaults:

- remove npm publish tokens, GitHub tokens, cloud credentials, and SSH agent variables;
- use a temporary isolated `HOME`;
- default to `--ignore-scripts`;
- allow lifecycle scripts only when an exact script-hash allowlist entry matches;
- restrict registry access to approved registry hosts where platform support exists;
- preserve package-manager compatibility for npm and pnpm.

The first implementation should be honest about platform limits. On systems where network allowlisting cannot be enforced by the tool, the mode must report that limitation in JSON and console output.

## Phase 8: npm-gate Published Dependency Tree Hardening

Harden the CLI's own publication posture. The repository uses `pnpm-lock.yaml` for development reproducibility, but published npm packages do not include `package-lock.json`. Add a release process that creates and verifies an exact published dependency tree, for example with `npm-shrinkwrap.json` or a documented equivalent strategy.

This phase should add checks, not silently mutate dependencies during normal analysis. Lifecycle scripts remain disabled during verification unless explicitly required.

## Cross-Cutting Compatibility Rules

- JSON output compatibility is preserved. New fields are additive.
- Existing signal IDs remain stable unless a new ID is required for a genuinely new risk.
- Existing CLI flags keep their current meaning.
- New config fields default to current behavior unless the production profile explicitly opts into stricter behavior.
- New network access is opt-in and injectable for tests.
- New process execution is isolated behind explicit interfaces and can be mocked.
- Policy continues to fail closed for high-confidence execution risk.

## Verification Matrix

Each implementation phase must run its focused unit tests first. Before reporting implementation complete for a phase, run the relevant subset of:

```sh
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm smoke:pack
```

For docs-only spec and plan work, verify that the new docs contain no placeholder language and that the git diff contains only intended roadmap artifacts.

## Feedback Coverage

| Feedback Item | Roadmap Coverage |
| --- | --- |
| CI example installs before scanning | Phase 1 |
| `ci --release-audit` should be recommended | Already present, reinforced in Phase 1 docs |
| Cryptographic npm signatures and Sigstore | Phase 5 |
| Trusted publishing enforcement | Phase 4 |
| pnpm/yarn lockfile security parity | Phase 2 |
| Live malicious-package intelligence | Phase 6 |
| Typosquat config deployment gap | Phase 4 docs and policy examples |
| Enforced install isolation | Phase 7 |
| `NPM_GATE_MODE=off` CI bypass | Phase 1 |
| Published dependency tree hardening | Phase 8 |
| Invisible Unicode and full-file scanning | Phase 3 |

## Sequencing

Phases 1 through 3 should be implemented first because they reduce current risk with bounded code changes. Phases 4 through 6 add policy and verification depth. Phase 7 is the largest runtime-behavior change and should start only after the policy and verifier interfaces are stable. Phase 8 can run in parallel with later phases because it concerns the repository's release posture rather than scanner behavior.

## Spec Self-Review

- No production code is changed by this design document.
- Each roadmap item maps to a phase.
- The design keeps analysis non-executing by default.
- The design preserves JSON compatibility.
- The design requires local or injected test fixtures for network and verifier behavior.
