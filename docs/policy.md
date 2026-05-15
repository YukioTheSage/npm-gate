# Policy

The default policy balances local developer velocity with CI enforcement.

| Setting                                      | Default                                               |
| -------------------------------------------- | ----------------------------------------------------- |
| `profile`                                    | `default`                                             |
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

Profiles:

- `default`: local-friendly static policy with CI-specific blocking.
- `production`: requires registry tarball inspection, transitive dependency inspection, integrity matching, workflow SHA pinning, release cache blocking, credential-harvesting and install-downloader blocking, and local advisory availability.
- `audit-only`: keeps findings visible while disabling hard blocks that would otherwise stop install decisions.

Every decision includes package name, version, score, severity, reasons, evidence, remediation, and whether an exception can override the finding.

## Direct Source Policy

- `local-directory` sources are inspected by reading only the target `package.json`.
- `local-tarball` sources are checked with safe tar path validation, static filename analysis, SHA-256 evidence, and a capped `package/package.json` manifest read.
- `remote-tarball` sources are inspected only when the URL belongs to the configured npm registry or `registry.npmjs.org`.
- `remote-tarball-unsupported` sources and arbitrary remote tarball hosts are blocked.
- `git` sources are not cloned. They warn locally and block in `ci`, `block`, or strict mode.

Info-only evidence such as a tarball hash does not create a warning by itself. Lifecycle scripts, unsafe or unreadable sources, missing manifests, suspicious tarball entries, credential-harvesting patterns, install downloaders, unsupported remote tarballs, and configured-registry fetch failures are normal policy signals.

## Production CI Policy

`npm-gate ci` forces production policy and strict exit behavior. It adds project-level findings for package-lock tarball hosts outside `approvedRegistryHosts`, package-lock integrity changes against an optional baseline, transitive registry dependency inspection, and dangerous GitHub Actions patterns such as `pull_request_target` plus untrusted checkout, cache use across privileged workflows, broad token permissions, and actions not pinned to full commit SHAs.

Required intelligence sources fail closed in CI. `local` is satisfied by the local advisory file path even when no records exist. `osv` uses the OSV querybatch-compatible intelligence client when configured.
