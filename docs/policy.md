# Policy

The default policy balances local developer velocity with CI enforcement.

| Setting                                      | Default                                               |
| -------------------------------------------- | ----------------------------------------------------- |
| `profile`                                    | `default`                                             |
| `policyMode`                                 | `balanced`                                            |
| `minimumReleaseAgeHours`                     | `72`                                                  |
| `blockLifecycleScripts`                      | `true` for first-seen packages or new lifecycle hooks |
| `warnLifecycleScripts`                       | `true` for known packages                             |
| `blockGitDependencies`                       | `true` in CI                                          |
| `warnGitDependencies`                        | `true` locally                                        |
| `requireProvenanceForHighImpactPackages`     | `false`                                               |
| `warnMissingProvenanceWhenPreviouslyPresent` | `true`                                                |
| `warnMissingRegistrySignature`               | `true` when signature data is available               |
| `blockNewPackageNamesInCI`                   | `true` unless allowlisted                             |
| `blockSuspiciousNameConfusion`               | `true`                                                |
| `blockKnownMaliciousAdvisories`              | `true`                                                |
| `warnUnknownPackages`                        | `true`                                                |
| `maxRiskScoreAllowed`                        | `70`                                                  |
| `maxRiskScoreWarn`                           | `40`                                                  |
| `allowOverridesWithJustification`            | `true` locally                                        |
| `disallowOverridesInCI`                      | `true`                                                |
| `approvedRegistryHosts`                      | `["registry.npmjs.org"]`                              |
| `requiredIntelligenceSources`                | `[]`                                                  |
| `requireTarballInspection`                   | `false`                                               |
| `requireIntegrityMatch`                      | `false`                                               |
| `inspectTransitiveDependencies`              | `false`                                               |
| `maxDependencyClosurePackages`               | `250`                                                 |
| `blockCredentialHarvestingPatterns`          | `true` in CI/production                              |
| `blockInstallDownloaders`                    | `true` in CI/production                              |
| `requireWorkflowShaPinning`                  | `false`                                               |
| `forbidReleaseCaches`                        | `false`                                               |
| `expectedProvenance`                         | `[]`                                                  |
| `sourceVerification`                         | `{ "enabled": false, "rules": [] }`                   |
| `emergencyDenylist`                          | `[]`                                                  |

Profiles:

- `default`: local-friendly static policy with CI-specific blocking.
- `production`: requires registry tarball inspection, transitive dependency inspection, integrity matching, workflow SHA pinning, release cache blocking, credential-harvesting and install-downloader blocking, and local advisory availability.
- `audit-only`: keeps findings visible while disabling hard blocks that would otherwise stop install decisions.

Policy modes:

- `balanced`: blocks obvious install-time execution risk, reports lower-confidence risk as warning or manual review, and preserves local developer velocity.
- `strict`: fails block and manual-review decisions. This mode is selected by `npm-gate ci`, `NPM_GATE_MODE=ci`, `profile: "production"`, and production scans unless overridden.
- `emergency`: blocks every non-info signal unless a narrow lifecycle script allowlist entry matches. It is intended for active incident response and local denylist lockfile rescans.

Every finding includes package or workflow target, version when applicable, decision, score, severity, reasons, evidence, remediation, and whether an exception can override the finding. Newer reports also include additive fields such as `riskCategory`, `matchedSignals`, `evidenceSummary`, `recommendedFix`, `policyMode`, `allowlist`, and `dependencyPath`. Existing JSON consumers can keep using the original fields.

## Decision Model

Decisions are `allow`, `warn`, `manual_review`, or `block`.

- `allow`: no actionable policy issue or a narrow allowlist entry matched.
- `warn`: visible risk that does not fail balanced local usage.
- `manual_review`: install or release should pause for human review. It fails under strict and emergency exit semantics.
- `block`: deterministic high-confidence risk, emergency denylist hit, unsafe source, or policy threshold breach.

## Direct Source Policy

- `local-directory` sources are inspected by reading only the target `package.json`.
- `local-tarball` sources are checked with safe tar path validation, static filename analysis, SHA-256 evidence, and a capped `package/package.json` manifest read.
- `remote-tarball` sources are inspected only when the URL belongs to the configured npm registry or `registry.npmjs.org`.
- `remote-tarball-unsupported` sources and arbitrary remote tarball hosts are blocked.
- `git` sources are not cloned. They warn locally and block in `ci`, `block`, or strict mode.

Info-only evidence such as a tarball hash does not create a warning by itself. Lifecycle scripts, unsafe or unreadable sources, missing manifests, suspicious tarball entries, credential-harvesting patterns, install downloaders, unsupported remote tarballs, and configured-registry fetch failures are normal policy signals.

## Lifecycle Execution Policy

npm-gate inspects `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`, `prepack`, `postpack`, and suspicious `pre*` or `post*` script variants. High-risk script signals include shell interpreters, downloader commands, shell pipes, PowerShell web requests, global package installs, `chmod +x` followed by execution, package-manager recursion, Bun or runtime bootstrap behavior, direct native binary execution, base64 payloads, `eval`, and `Function` constructor use.

Strict mode blocks new or changed lifecycle scripts and high-risk install-time patterns. Balanced mode blocks obvious execution risk and marks newly added lifecycle hooks for manual review. Emergency mode blocks all new or changed lifecycle scripts unless an exact script hash allowlist entry matches.

Package allowlists are not lifecycle execution allowlists. A lifecycle script allowlist entry must include package name, exact version, script name, SHA-256 of the exact command, non-empty justification, optional expiry, and integrity or tarball hash when available. Package-name-only lifecycle allowlists are rejected because they would let future authenticated publishes execute new code without review.

## Artifact And Dependency Delta Policy

Artifact diffing compares package manifests, dependency additions and removals, script additions or changes, binary and suspicious file additions, package-size deltas, repository metadata changes, and tarball/source mismatch metadata when available. When tarball inspection is enabled, npm-gate fetches the current and nearest previous version tarballs through the registry client, reuses the tarball cache, and compares their entry lists and package sizes. Package.json-only lifecycle additions block. Patch or minor releases that add dependencies require review, and a newly added dependency with an install script or high-confidence typosquat signal blocks.

Dependency delta analysis compares direct and transitive dependency closures. Package-lock paths are reported for direct and nested packages when the lockfile contains enough path metadata, and newly introduced transitive packages include a dependency path so hidden dependency injection is visible even when the top-level package is popular or has a legitimate maintainer.

## Typosquat And Dependency Confusion Policy

Name-confusion checks compare packages to configured protected names and a small built-in set of common ecosystem packages. Signals include edit distance, missing or extra separators, token-order confusion, suffix or prefix additions, scoped/unscoped confusion, and namespace confusion. High-confidence findings block. Medium-confidence findings require manual review. Low-confidence name similarity remains a warning.

## Provenance Policy

Provenance proves publish path, not package safety. Expected repository, workflow, ref, and commit subject can be configured per package, and mismatches block under strict policy. Provenance and trusted publishing never suppress lifecycle-script, artifact-diff, dependency-delta, typosquat, frontend runtime, or CI trust-boundary findings.

Optional source verification is separate from npm provenance. It can verify configured GitHub repository tags and commits for selected packages:

```json
{
  "sourceVerification": {
    "enabled": true,
    "rules": [
      {
        "package": "@company/core",
        "repository": "company/core",
        "tagTemplate": "v{version}",
        "commit": "expected-release-commit",
        "required": true
      }
    ]
  }
}
```

Repository values may be `owner/repo`, `https://github.com/owner/repo`, or `.git` URLs. Required failures block in strict and emergency mode. Optional failures require review. Tests should use an injected verifier and must not depend on live GitHub access.

## Production CI Policy

`npm-gate ci` forces production policy and strict exit behavior. It adds project-level findings for package-lock tarball hosts outside `approvedRegistryHosts`, package-lock integrity changes against an optional baseline, bounded transitive registry dependency inspection, direct registry tarball inspection, and dangerous GitHub Actions patterns such as `pull_request_target` plus untrusted checkout, cache use across privileged workflows, broad token permissions, and actions not pinned to full commit SHAs.

Transitive dependency tarball inspection is opt-in with `--deep-tarballs`. This keeps normal CI runtime bounded while still allowing slower release audits to fetch and inspect transitive package artifacts.

Required intelligence sources fail closed in CI. `local` is satisfied by the local advisory file path even when no records exist. `osv` uses the OSV querybatch-compatible intelligence client when configured.

## Frontend Runtime Policy

Bounded tarball samples are scanned for browser runtime risk: wallet provider access, clipboard mutation, transaction object mutation, DOM injection, fetch/XHR/WebSocket interception, CDN `latest` references, external scripts without SRI, and newly introduced obfuscated payloads. Strict mode blocks newly introduced wallet, clipboard, and transaction-manipulation behavior in dependency updates unless explicitly reviewed.

## Credential Exposure Policy

Credential exposure checks report categories only. They detect npm token environment variables, GitHub token environment variables, cloud credential environment variables, SSH agent presence, `.npmrc` token categories, CI secrets context, writable home, and sensitive local paths. Secret values are never included in human, JSON, or SARIF output.

## Emergency Denylist Policy

Emergency mode consumes only local config. It blocks configured package/version denylist entries in direct or transitive lockfile paths, reports affected dependency paths, and prints credential-rotation and CI-cleanup checklists. npm-gate does not pull live incident feeds.
