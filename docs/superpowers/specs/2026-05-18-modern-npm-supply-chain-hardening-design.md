# Modern npm Supply Chain Hardening Design

## Context

The goal is to make npm-gate protect release and automation paths against modern npm supply-chain attacks. The repository already implements many roadmap pieces: release-age checks, lifecycle-script analysis, tarball inspection, transitive dependency inspection, lockfile checks, GitHub Actions workflow analysis, provenance and trusted-publishing signals, cryptographic signature verifier hooks, signed incident feeds, source verification, emergency denylist support, and sandboxed package-manager delegation with environment scrubbing.

The remaining hardening should favor CI and production protection over local developer convenience. Local default usage can continue to warn by default, but release gates should fail closed on high-confidence attack indicators.

## Goals

- Strengthen CI and production policy behavior using controls already present in the codebase.
- Make strict release gates block modern attack patterns such as install-time downloaders, obfuscated lifecycle scripts, new patch dependencies, exotic sources, unsafe workflow trust boundaries, and missing required intelligence.
- Require transitive release-age evaluation and deep artifact analysis in release-audit paths.
- Provide clear remediation in JSON and console output without changing existing JSON fields.
- Add tests for every policy or analyzer behavior change.

## Non-Goals

- Do not execute package code during analysis.
- Do not add VM, Firecracker, gVisor, or OS-level network containment in this phase.
- Do not add production dependencies unless the change has a clear security and maintenance reason.
- Do not fetch arbitrary Git repositories or remote tarball hosts during analysis.
- Do not let provenance, signatures, trusted publishing, package popularity, or maintainer legitimacy bypass lifecycle, artifact, dependency, frontend runtime, workflow, or lockfile checks.
- Do not expose secrets or credential values in output, tests, docs, or reports.

## Recommended Architecture

Use the existing policy profile and analyzer architecture. The `production` profile and `npm-gate ci` remain the protected automation path. The implementation should adjust defaults and decision behavior only where the current analyzer evidence is deterministic enough to defend a release gate.

The primary implementation units are:

- Config loading: tighten production profile defaults and keep local `default` profile usable.
- Policy engine: make strict and production gates block high-confidence modern attack signals that are currently only manual-review or warning.
- Engine release-audit path: ensure transitive dependency inspection and deep tarball inspection are active together for release gates.
- Analyzer coverage: expand or harden existing tests around patch dependency additions, Git and remote tarball sources, downloader and obfuscation lifecycle patterns, workflow SHA pinning, signed feed fail-closed behavior, and signature/provenance requirements.
- Documentation: make the recommended release command and policy expectations explicit.

## Policy Design

CI and production should be the high-protection defaults:

- `npm-gate ci` uses production profile, strict policy mode, direct tarball inspection, registry integrity checks, workflow SHA pinning, release-cache blocking, credential-pattern scanning, and transitive dependency inspection.
- `npm-gate ci --release-audit` additionally performs deep transitive tarball inspection and should be the documented release gate.
- Git dependencies and unsupported remote tarballs block in strict, CI, block, and emergency modes.
- Lifecycle scripts block when lifecycle blocking is enabled; new or changed lifecycle hooks require review locally and fail strict release gates.
- Install-time downloader, shell pipe, Bun/runtime bootstrap, base64, `eval`, `Function`, native loader, and credential/network exfiltration patterns remain hard blocks where already detected.
- Patch and minor releases that add dependencies should fail strict release gates unless reviewed through the existing exception or allowlist mechanisms.
- Signed incident feeds and OSV remain opt-in, but configured required intelligence sources fail closed when unavailable.
- Cryptographic signature verification remains configurable because the default verifier depends on the local npm CLI. When `requireCryptographicSignatureVerification` is enabled, unavailable, missing, invalid, or unverified evidence blocks.

## Data Flow

1. CLI command resolves runtime mode, policy profile, and policy mode.
2. Config loader applies production defaults for `npm-gate ci` or explicit production scans.
3. Engine collects project candidates from package manifests and lockfiles.
4. Registry candidates are evaluated with metadata, release age, lifecycle scripts, dependency deltas, advisories, provenance, trusted publishing, source verification, signatures, and tarball inspection.
5. When transitive inspection is enabled, dependency closure evaluation applies the same release-age, advisory, provenance, signature, and dependency-delta checks to transitive packages.
6. Project policy analyzers inspect lockfiles, runtime source references, workflows, and credential exposure.
7. Policy engine converts signals into `allow`, `warn`, `manual_review`, or `block`.
8. Reporters emit additive JSON and human output with reasons and remediation.

## Error Handling

High-confidence release risk should fail closed in CI and production. Unavailable required intelligence, uninspectable required tarballs, integrity mismatches, unsafe workflow trust boundaries, and missing required cryptographic verification evidence block. Optional sources should warn or require review rather than silently claiming safety. Any unavailable external verifier or feed must report the source and failure category without exposing secrets.

## Testing

Use test-first implementation for behavior changes. Focused tests should cover:

- production profile default changes;
- strict blocking for patch/minor dependency additions;
- release-audit activation of transitive and deep tarball checks;
- required signature verification failure behavior;
- required signed-feed failure behavior;
- lifecycle downloader and obfuscation hard blocks;
- workflow SHA pinning and dangerous trust-boundary blocking;
- JSON compatibility for additive report fields.

Before reporting implementation complete, run the relevant subset:

```sh
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm smoke:pack
```

## Spec Self-Review

- Scope is focused on strict CI and production hardening, not local warn-mode friction.
- The design does not require executing package code during analysis.
- The design preserves existing JSON fields and allows only additive output changes.
- The design keeps live or external sources opt-in unless explicitly configured as required.
- Each planned behavior change has a corresponding test expectation.
