# npm-gate

npm-gate is a defensive npm supply-chain security system. It wraps common npm commands, evaluates dependency risk before install, enforces local or CI policy, and writes auditable evidence for each allow, warning, or block decision.

Dependency installation is code execution. npm lifecycle hooks such as `preinstall`, `install`, `postinstall`, `prepare`, `prepack`, and `postpack` can run arbitrary code during package installation. npm-gate treats installation as a security gate, not a blind package manager operation.

## Installation

```sh
pnpm install
pnpm build
pnpm link --global
```

Node.js 20.17.0 or newer is required. The package exposes the `npm-gate` binary.

## Quick Start

```sh
npm-gate policy init
npm-gate scan
npm-gate install axios
npm-gate install --dry-run --json
npm-gate ci --json
```

## CLI Examples

```sh
npm-gate install
npm-gate install axios
npm-gate install axios --package-manager pnpm
npm-gate add lodash
npm-gate ci
npm-gate audit
npm-gate scan
npm-gate explain workflow-cache-poisoning-risk:.github/workflows/release.yml
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

By default, local mode allows warnings and blocks only high-risk findings. Use `--strict` to convert warnings into blocks and `--no-execute` or `--dry-run` to prevent npm delegation.

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

Set `NPM_GATE_MODE=ci` and run `npm-gate scan --production` or `npm-gate ci`. The `ci` command forces the production profile, strict failure semantics, registry tarball inspection, lockfile checks, and GitHub workflow checks.

```yaml
- run: pnpm exec npm-gate ci --json
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
  "minimumReleaseAgeHours": 72,
  "blockLifecycleScripts": true,
  "blockGitDependencies": true,
  "protectedPackageNames": ["react", "lodash", "@company/core"],
  "highImpactPackageNames": ["@company/core"],
  "approvedRegistryHosts": ["registry.npmjs.org", "registry.company.test"],
  "requiredIntelligenceSources": ["local"],
  "requireTarballInspection": true,
  "requireIntegrityMatch": true,
  "inspectTransitiveDependencies": true,
  "maxDependencyClosurePackages": 250,
  "blockCredentialHarvestingPatterns": true,
  "blockInstallDownloaders": true,
  "requireWorkflowShaPinning": true,
  "forbidReleaseCaches": true
}
```

JSON is supported. YAML config is intentionally not enabled in this minimal dependency set.

## Policy Example

The default policy warns on unknown packages, suspicious name confusion, suspicious static tarball content, missing provenance when required, and missing registry signature data when available. It blocks known malicious advisories, suspicious lifecycle additions, CI-only new package names, unapproved lockfile hosts, registry tarball integrity mismatches, dangerous workflow trust boundaries, CI or production credential-harvesting and install-downloader patterns, and scores above the configured block threshold.

## Report Example

```json
{
  "summary": { "allow": 1, "warn": 1, "block": 0, "suppressed": 0 },
  "mode": "warn",
  "findings": [
    {
      "package": "example",
      "version": "1.2.3",
      "decision": "warn",
      "score": 45,
      "reasons": ["Lifecycle script detected"]
    }
  ]
}
```

## Limitations

npm-gate uses deterministic static heuristics. It does not execute package code, does not perform live detonation, does not clone Git sources, does not fetch arbitrary remote tarball hosts, does not claim complete cryptographic provenance verification, and cannot catch all malicious code that activates only at runtime. Production policy inspects transitive registry dependencies and bounded source samples from tarballs, but obfuscated runtime-only malware can still evade static rules. Provenance and signatures are treated as evidence, not as sufficient proof that a release pipeline was safe. Registry metadata, signatures, and provenance are reported as `unknown` or `unavailable` when the implemented registry path cannot verify them.

## Security Model

The tool is defensive-only. It only fetches npm registry metadata or registry tarballs needed for package analysis. Local tarball and directory installs are inspected statically and never executed during analysis. It does not read credential files except npm configuration paths needed for registry discovery and redaction. It redacts tokens from logs, does not access cloud metadata services, and never runs lifecycle scripts during analysis.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions should include tests, keep fixtures synthetic and inert, and preserve the defensive-only scope.

## License

Apache-2.0. See [LICENSE](LICENSE).
