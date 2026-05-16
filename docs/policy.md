# Policy

The default policy balances local developer velocity with CI enforcement.

| Setting                                      | Default                                         |
| -------------------------------------------- | ----------------------------------------------- |
| `profile`                                    | `default`                                       |
| `policyMode`                                 | `balanced`                                      |
| `minimumReleaseAgeHours`                     | `72`                                            |
| `blockLifecycleScripts`                      | `true`                                          |
| `warnLifecycleScripts`                       | `true` schema default; not separately consulted |
| `blockGitDependencies`                       | `true`                                          |
| `warnGitDependencies`                        | `true` schema default; local git findings warn  |
| `requireProvenanceForHighImpactPackages`     | `false`                                         |
| `warnMissingProvenanceWhenPreviouslyPresent` | `true` schema default; not separately consulted |
| `warnMissingRegistrySignature`               | `true` when signature data is available         |
| `blockNewPackageNamesInCI`                   | `true` unless allowlisted                       |
| `blockSuspiciousNameConfusion`               | `true`                                          |
| `blockKnownMaliciousAdvisories`              | `true`                                          |
| `warnUnknownPackages`                        | `true` schema default; unknowns currently warn  |
| `maxRiskScoreAllowed`                        | `70`                                            |
| `maxRiskScoreWarn`                           | `40`                                            |
| `allowOverridesWithJustification`            | `true` locally                                  |
| `disallowOverridesInCI`                      | `true`                                          |
| `approvedRegistryHosts`                      | `["registry.npmjs.org"]`                        |
| `requiredIntelligenceSources`                | `[]`                                            |
| `requireTarballInspection`                   | `false`                                         |
| `requireIntegrityMatch`                      | `false`                                         |
| `inspectTransitiveDependencies`              | `false`                                         |
| `maxDependencyClosurePackages`               | `250`                                           |
| `blockCredentialHarvestingPatterns`          | `true`; hard-blocks in CI/production            |
| `blockInstallDownloaders`                    | `true`; hard-blocks in CI/production            |
| `requireWorkflowShaPinning`                  | `false`                                         |
| `forbidReleaseCaches`                        | `false`                                         |
| `expectedProvenance`                         | `[]`                                            |
| `sourceVerification`                         | `{ "enabled": false, "rules": [] }`             |
| `emergencyDenylist`                          | `[]`                                            |

Profiles:

- `default`: local-friendly static policy with CI-specific blocking.
- `production`: requires registry tarball inspection, transitive dependency inspection, integrity matching, workflow SHA pinning, release cache blocking, credential-harvesting and install-downloader blocking, and sets `requiredIntelligenceSources` to `["local"]`.
- `audit-only`: relaxes configurable hardening flags and raises the score block threshold while keeping findings visible. Non-overridable hard-block signals, such as integrity mismatches or unsafe workflow trust boundaries, can still block.

Policy modes:

- `balanced`: blocks obvious install-time execution risk, reports lower-confidence risk as warning or manual review, and preserves local developer velocity.
- `strict`: fails warning, manual-review, and block decisions at the command exit-code layer. This mode is selected by `npm-gate ci`, `NPM_GATE_MODE=ci`, `profile: "production"`, and production scans unless overridden.
- `emergency`: blocks every non-info signal unless a narrow lifecycle script allowlist entry matches. It is intended for active incident response and local denylist lockfile rescans.

Runtime modes:

- `warn`: default local enforcement; warnings do not fail the command.
- `block`: turns warning decisions into block decisions.
- `ci`: applies CI semantics and selects strict policy mode unless explicitly overridden.
- `off`: disables enforcement decisions. For `install` and `add`, it delegates directly unless `--dry-run` or `--no-execute` is set.

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
- `git` sources are not cloned. They warn locally and block in `ci`, `block`, strict, or emergency mode.

Info-only evidence such as a tarball hash does not create a warning by itself. Lifecycle scripts, unsafe or unreadable sources, missing manifests, suspicious tarball entries, credential-harvesting patterns, install downloaders, unsupported remote tarballs, and configured-registry fetch failures are normal policy signals.

## Lifecycle Execution Policy

npm-gate inspects `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`, `prepack`, `postpack`, and suspicious `pre*` or `post*` script variants. High-risk script signals include shell interpreters, downloader commands, shell pipes, PowerShell web requests, global package installs, `chmod +x` followed by execution, package-manager recursion, Bun or runtime bootstrap behavior, direct native binary execution, Windows native loader execution such as `rundll32` or `regsvr32`, base64 payloads, `eval`, and `Function` constructor use.

Strict mode blocks new or changed lifecycle scripts and high-risk install-time patterns. Balanced mode blocks detected lifecycle scripts when `blockLifecycleScripts` is enabled and marks newly added lifecycle hooks for manual review. Emergency mode blocks all new or changed lifecycle scripts unless an exact script hash allowlist entry matches.

Package allowlists are not lifecycle execution allowlists. The script allowlist file is `.npm-gate/script-allowlist.json` and must be a JSON object with an `allowlist`, `entries`, or `scripts` array. Each lifecycle script allowlist entry must include package name, exact version, script name, SHA-256 of the exact command, non-empty justification, optional expiry, and registry integrity when available. Package-name-only lifecycle allowlists are rejected because they would let future authenticated publishes execute new code without review.

## Artifact And Dependency Delta Policy

Artifact diffing compares package manifests, dependency additions and removals, script additions or changes, binary and suspicious file additions, package-size deltas, file-count deltas, repository metadata changes, and tarball/source mismatch metadata when available. When tarball inspection is enabled, npm-gate fetches the current and nearest previous version tarballs through the registry client, reuses the tarball cache, and compares their entry lists and package sizes. Patch or minor releases are flagged when package size grows at least 3x and by at least 100KB, or by at least 1MB regardless of ratio. Large file-count spikes in patch or minor releases also require review. Package.json-only lifecycle additions block. Patch or minor releases that add dependencies require review, and a newly added dependency with an install script or high-confidence typosquat signal blocks.

Dependency delta analysis compares direct and transitive dependency closures. Package-lock paths are reported for direct and nested packages when the lockfile contains enough path metadata, and newly introduced transitive packages include a dependency path so hidden dependency injection is visible even when the top-level package is popular or has a legitimate maintainer.

## Typosquat And Dependency Confusion Policy

Name-confusion checks compare packages to configured `protectedPackageNames`. Signals include edit distance, missing or extra separators, token-order confusion, suffix or prefix additions, and scoped/unscoped confusion. The current analyzer emits medium- or high-confidence `name-confusion` signals; with `blockSuspiciousNameConfusion` enabled, emitted name-confusion signals block.

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
        "packageJsonPath": "package.json",
        "required": true
      }
    ]
  }
}
```

Repository values may be `owner/repo`, `https://github.com/owner/repo`, or `.git` URLs. `packageJsonPath` defaults to `package.json`. When a source ref is available, npm-gate compares the published manifest with the configured source manifest for lifecycle scripts, dependency sections, `bin`, `main`, `exports`, `files`, and repository metadata. The default verifier queries `api.github.com` when source verification is enabled. Required failures block in strict and emergency mode. Optional failures require review. Tests should use an injected verifier and must not depend on live GitHub access.

## Production CI Policy

`npm-gate ci` forces production policy and strict exit behavior. It adds project-level findings for package-lock tarball hosts outside `approvedRegistryHosts`, package-lock integrity changes against an optional baseline, bounded transitive registry dependency inspection, direct registry tarball inspection, and dangerous GitHub Actions patterns such as `pull_request_target` plus untrusted checkout, cache use across privileged workflows, broad token permissions, and actions not pinned to full commit SHAs.

Transitive dependency tarball inspection is opt-in with `--deep-tarballs` or the clearer `npm-gate ci --release-audit` shortcut. This keeps normal CI runtime bounded while still allowing slower release and incident audits to fetch and inspect transitive package artifacts.

Configured OSV intelligence fails closed when `osv` is required and unavailable. `local` is treated as the built-in local advisory feed and is satisfied even when `npm-gate-advisories.json` is absent or contains no records. `npm-audit` advisories are supplied by the `npm-gate audit` command; the current `requiredIntelligenceSources` enforcement path does not launch `npm audit` on its own.

## Frontend Runtime Policy

Bounded tarball samples are scanned for browser runtime risk: wallet provider access, clipboard mutation, transaction object mutation, DOM injection, fetch/XHR/WebSocket interception, CDN `latest` references, external scripts without SRI, and newly introduced obfuscated payloads. Project source files are scanned for external script tags that use CDN `latest` or omit SRI, excluding dependency, build, and cache directories. Strict mode blocks newly introduced wallet, clipboard, transaction-manipulation, and project CDN `latest` behavior unless explicitly reviewed; missing SRI requires manual review and therefore fails strict exit semantics.

## Credential Exposure Policy

Credential exposure checks report categories only. They detect npm token environment variables, GitHub token environment variables, cloud credential environment variables, SSH agent presence, `.npmrc` token categories, CI secrets context, writable home, and sensitive local paths. Secret values are never included in human, JSON, or SARIF output.

## Emergency Denylist Policy

Emergency mode consumes only local config. It blocks configured package/version denylist entries in direct or transitive lockfile paths, reports affected dependency paths, and prints credential-rotation and CI-cleanup checklists. npm-gate does not pull live incident feeds. Import external incident data into `npm-gate-advisories.json` or `emergencyDenylist` after local review.
