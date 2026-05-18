# npm-gate

npm-gate is a defensive npm supply-chain security system. It wraps common npm commands, evaluates dependency risk before install, enforces local or CI policy, and writes auditable evidence for each allow, warning, or block decision.

Dependency installation is code execution. npm lifecycle hooks such as `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`, `prepack`, and `postpack` can run arbitrary code during package installation. npm-gate treats installation as a security gate, not a blind package manager operation.

## Installation

```sh
pnpm install --ignore-scripts
pnpm build
pnpm link --global
```

Node.js 20.17.0 or newer is required. The package exposes the `npm-gate` binary.
Release dependency-tree checks are documented in [docs/release-hardening.md](docs/release-hardening.md).

## Quick Start

```sh
npm-gate policy init
npm-gate scan
npm-gate scan --policy-mode strict
npm-gate install axios
npm-gate install --dry-run --json
npm-gate ci --json
npm-gate ci --release-audit --json
npm-gate emergency --json
```

## CLI Examples

```sh
npm-gate install
npm-gate install axios
npm-gate install axios --package-manager pnpm
npm-gate add lodash
npm-gate ci
npm-gate ci --release-audit
npm-gate ci --previous-package-lock ../baseline/package-lock.json
npm-gate audit
npm-gate scan
npm-gate scan --tarballs
npm-gate scan --policy-mode emergency
npm-gate emergency
npm-gate explain workflow-cache-poisoning-risk:.github/workflows/release.yml
npm-gate install ./pkg.tgz --sandbox-plan
npm-gate install axios --sandbox-execute
npm-gate doctor
npm-gate report --format json
npm-gate allow axios@1.6.0 --reason "SEC-123 approved review"
npm-gate config show
```

## Local Developer Usage

Use aliases to route install-like commands through the wrapper:

```sh
alias npmi="npm-gate install"
alias npmci="npm-gate ci"
```

By default, local mode uses balanced policy, allows warnings, and blocks high-confidence execution risk. Use `--policy-mode strict` or `--strict` to convert warnings and manual-review findings into failed gates. Use `--no-execute` or `--dry-run` to prevent npm delegation.

`install` and `add` delegate to `pnpm` when `pnpm-lock.yaml` exists, otherwise `npm`. Override with `--package-manager npm|pnpm` or `NPM_GATE_PACKAGE_MANAGER=npm|pnpm`. `--sandbox-plan` prints the static, non-executing analysis plan and never delegates to a package manager. `--sandbox-execute` delegates only after policy allows, with publish tokens, GitHub tokens, cloud credentials, and SSH agent variables removed; it uses an isolated temporary home and appends `--ignore-scripts`.

## Policy Modes

- `balanced`: local developer default. Blocks obvious install-time execution risk and reports lower-confidence risk as warnings or manual review.
- `strict`: CI and production default. Blocks high-confidence risk, fails warning and manual-review findings at exit, inspects transitive dependencies when configured, and treats unsafe CI trust boundaries as release blockers.
- `emergency`: incident-response mode. Blocks every non-info signal unless a narrow script allowlist entry matches, consumes only local emergency denylist config, rescans lockfiles, and prints credential-rotation plus CI-cleanup checklists.

`NPM_GATE_POLICY_MODE=balanced|strict|emergency` overrides config. `npm-gate ci`, `NPM_GATE_MODE=ci`, `profile: "production"`, and `--production` select strict behavior unless explicitly overridden.

Runtime mode is separate from policy mode. `NPM_GATE_MODE=warn` is the default, `block` turns warning decisions into block decisions, `ci` enables CI semantics, and `off` disables enforcement; for `install` and `add`, `off` delegates directly unless `--dry-run` or `--no-execute` is set. `off` is rejected in CI or release contexts such as `CI=true`, `GITHUB_ACTIONS=true`, or `NPM_GATE_RELEASE=true`.

## Direct Source Installs

Direct local sources are inspected before npm runs:

```sh
npm-gate install ./pkg.tgz --dry-run --json
npm-gate install file:./pkg --dry-run
npm-gate install link:./pkg --dry-run
npm-gate install https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz --dry-run --json
```

Local directories are checked by reading their `package.json`. Local and configured-registry tarballs are streamed through safe tar path validation, hashed, and inspected for `package/package.json` and suspicious filenames. Clean inspected sources install normally. Warnings install in local mode, but block with `--strict` or `NPM_GATE_MODE=block`. Block findings never delegate to npm.

Direct remote tarball URLs are inspected only when they belong to the configured npm registry or `registry.npmjs.org`; arbitrary remote hosts are blocked. Direct Git and GitHub specs are not cloned; they warn locally and block under `--strict`, `NPM_GATE_MODE=ci`, or `NPM_GATE_MODE=block`.

## CI Usage

Set `NPM_GATE_MODE=ci` and run `npm-gate scan --production` or `npm-gate ci`. The `ci` command forces the production profile, strict failure semantics, direct registry tarball inspection, lockfile checks, and GitHub workflow checks. For release and incident-response jobs, use `npm-gate ci --release-audit`; it enables production policy, strict exit behavior, direct tarball inspection, transitive dependency inspection, and deep tarball inspection for transitive packages. `--deep-tarballs` remains available when you only need the lower-level switch.

```yaml
- run: pnpm install --ignore-scripts --frozen-lockfile
- run: pnpm build
- run: node dist/index.js ci --release-audit --json
  env:
    NPM_GATE_MODE: ci
```

For one-off CI usage before adding `npm-gate` as a project dependency, pin an approved
version explicitly:

```yaml
- run: pnpm dlx npm-gate@<approved-version> ci --json
  env:
    NPM_GATE_MODE: ci
```

## Config Example

`npm-gate.config.json` is searched from the current directory upward.

```json
{
  "profile": "production",
  "policyMode": "strict",
  "minimumReleaseAgeHours": 72,
  "blockLifecycleScripts": true,
  "blockGitDependencies": true,
  "protectedPackageNames": ["react", "lodash", "@company/core"],
  "highImpactPackageNames": ["@company/core"],
  "requireTrustedPublishingForHighImpactPackages": true,
  "verifyRegistrySignatures": true,
  "requireCryptographicSignatureVerification": true,
  "approvedRegistryHosts": ["registry.npmjs.org", "registry.company.test"],
  "requiredIntelligenceSources": ["local", "signed-feed"],
  "signedIncidentFeeds": [
    {
      "path": "./security/npm-gate-incident-feed.json",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ],
  "requireTarballInspection": true,
  "requireIntegrityMatch": true,
  "inspectTransitiveDependencies": true,
  "maxDependencyClosurePackages": 250,
  "blockCredentialHarvestingPatterns": true,
  "blockInstallDownloaders": true,
  "requireWorkflowShaPinning": true,
  "forbidReleaseCaches": true,
  "expectedProvenance": [
    {
      "package": "@company/core",
      "repository": "company/core",
      "workflow": "release.yml",
      "ref": "refs/heads/main"
    }
  ],
  "trustedPublishing": [
    {
      "package": "@company/core",
      "repository": "company/core",
      "workflow": ".github/workflows/publish.yml",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  ],
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
  },
  "emergencyDenylist": [
    {
      "package": "compromised-package",
      "versions": ["1.2.3"],
      "reason": "Internal incident SEC-2026-001"
    }
  ]
}
```

JSON is supported. YAML config is intentionally not enabled in this minimal dependency set.

## Policy Example

The default policy warns on unknown packages, suspicious static tarball content, missing registry signature data when available, dependency deltas, and lower-confidence frontend runtime risk. When configured with `protectedPackageNames` or high-impact package rules, it also evaluates name-confusion, required provenance, and trusted-publishing expectations. It blocks known malicious advisories, high-risk lifecycle execution, downloader scripts, obfuscated install payloads, strict-mode Git dependencies, CI-only new package names, unapproved lockfile hosts, registry tarball integrity mismatches, dangerous workflow trust boundaries, CI or production credential-harvesting and install-downloader patterns, emergency denylist hits, project source CDN `latest` findings in strict gates, strict-release patch dependency additions, new binary or shell artifacts, obfuscated tarball code, invisible Unicode source controls, unsupported remote tarballs, and scores above the configured block threshold.

Provenance and trusted publishing are publish-path signals only. They never suppress lifecycle-script, artifact-diff, dependency-delta, typosquat, frontend runtime, or CI trust-boundary findings.

Cryptographic registry signature verification is opt-in. When `verifyRegistrySignatures` or `requireCryptographicSignatureVerification` is enabled, npm-gate uses the configured verifier; the default verifier runs `npm audit signatures --json` and caches the result for the project directory. Required verification failures are high-severity provenance-risk findings.

Signed incident feeds are also opt-in. A signed feed is verified before its advisory records are trusted. If `signed-feed` is listed in `requiredIntelligenceSources`, missing files, invalid keys, schema errors, and signature failures fail closed as unavailable intelligence.

When registry tarball inspection is enabled, npm-gate compares the current tarball with the nearest previous version when registry metadata provides a previous tarball. This detects binary additions, suspicious file additions, package size and file-count spikes, and manifest-only changes that do not appear in source metadata. If a previous tarball URL exists but cannot be inspected, npm-gate reports a manual-review artifact-diff signal.

Optional source verification can check configured GitHub repository tags and commits for selected packages. When a source ref is configured, npm-gate also compares the published package manifest with the configured source `package.json` path, defaulting to `package.json`. It is disabled by default and only runs for configured `sourceVerification.rules`. Required source verification failures block under strict and emergency policy.

Project source files are also scanned for CDN `@latest` script references and external browser scripts without Subresource Integrity. This catches script-tag consumption that bypasses package-manager installation gates.

## Lifecycle Script Allowlist

Package-name allowlists do not authorize lifecycle execution. To approve an install-time script, add `.npm-gate/script-allowlist.json` with an `allowlist`, `entries`, or `scripts` array containing an exact package, exact version, script name, SHA-256 of the exact command, non-empty justification, optional expiry, and registry integrity when available:

```json
{
  "allowlist": [
    {
      "package": "native-addon",
      "version": "1.0.0",
      "script": "install",
      "commandSha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "integrity": "sha512-reviewed-integrity",
      "expiresAt": "2026-06-30T00:00:00.000Z",
      "justification": "Reviewed native build bootstrap in SEC-42"
    }
  ]
}
```

If the script command, version, package, registry integrity, expiry, or justification changes, the entry no longer authorizes the script. This prevents broad package allowlists from becoming permanent install-time code execution bypasses.

## Report Example

```json
{
  "summary": { "allow": 1, "warn": 1, "block": 0, "suppressed": 0 },
  "mode": "warn",
  "policyMode": "balanced",
  "findings": [
    {
      "package": "example",
      "version": "1.2.3",
      "decision": "warn",
      "score": 45,
      "riskCategory": "lifecycle_script_risk",
      "matchedSignals": ["lifecycle-script"],
      "evidenceSummary": "postinstall script is present",
      "recommendedFix": "Review the package artifact before installation",
      "policyMode": "balanced",
      "dependencyPath": ["app@1.0.0", "example@1.2.3"],
      "reasons": ["Lifecycle script detected"]
    }
  ]
}
```

SARIF output keeps the existing rule/result shape and adds finding metadata such as decision, severity, risk category, policy mode, matched signals, dependency path, allowlist state, and kill-chain explanation under SARIF `properties`.

## Limitations

npm-gate uses deterministic static heuristics. It does not execute package code during analysis, does not perform live detonation, does not clone Git sources, does not fetch arbitrary remote tarball hosts, does not claim complete cryptographic provenance verification, and cannot catch all malicious code that activates only at runtime. Production policy inspects direct registry tarballs by default and keeps transitive dependency inspection bounded; `ci --release-audit` opts into exhaustive transitive tarball inspection for slower release and incident audits. Obfuscated runtime-only malware can still evade static rules. Provenance, signatures, legitimate maintainer identity, registry publish validity, signed incident feeds, and trusted publishing are treated as evidence, not as sufficient proof that a release pipeline was safe. Registry metadata, signatures, and provenance are reported as `unknown` or `unavailable` when the implemented registry path cannot verify them. Optional source verification uses GitHub metadata and configured source `package.json` files; optional OSV intelligence uses the OSV API when configured. `--sandbox-execute` reduces install exposure but does not enforce network allowlisting or OS-level containment.

## Security Model

The tool is defensive-only. By default it fetches npm registry metadata and registry tarballs needed for package analysis. When explicitly configured, it can also query OSV advisory data and GitHub source metadata or source `package.json` files for source verification. Local tarball and directory installs are inspected statically and never executed during analysis. Credential checks report categories only, such as npm token environment, GitHub token environment, cloud credential environment, SSH agent, `.npmrc` token category, CI secrets context, writable home, and sensitive local paths. Secret values are never printed. npm-gate does not access cloud metadata services and never runs lifecycle scripts during analysis.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should include tests, keep fixtures synthetic and inert, and preserve the defensive-only scope.

## License

Apache-2.0. See [LICENSE](LICENSE).
