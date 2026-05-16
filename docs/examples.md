# Examples

## Dry Run an Install

```sh
npm-gate install axios --dry-run
```

## Inspect a Local Tarball Before Install

```sh
npm-gate install ./pkg.tgz --dry-run --json
```

## Inspect a Configured-Registry Tarball Before Install

```sh
npm-gate install https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz --dry-run --json
```

Remote tarballs from arbitrary hosts are blocked. Configure the npm registry before using a private registry tarball URL.

## Inspect a Local Directory Before Install

```sh
npm-gate install file:./pkg --dry-run
```

Warnings install in local mode unless `--strict` is set. Blocked direct sources never delegate to npm.

## Gate a Direct Git Source

```sh
npm-gate install github:user/repo --dry-run --json
```

Direct Git sources are not cloned. They warn locally and block in strict, block, or CI modes.

## Strict CI Gate

```sh
NPM_GATE_MODE=ci npm-gate ci --json
```

## Compare a Package Lock Baseline

```sh
NPM_GATE_MODE=ci npm-gate ci --previous-package-lock ../baseline/package-lock.json --json
```

## Strict Local Gate Without Install Execution

```sh
npm-gate install axios --dry-run --policy-mode strict --json
```

## Scan Registry Tarballs

```sh
npm-gate scan --tarballs --json
```

## Print a Static Sandbox Plan

```sh
npm-gate install ./pkg.tgz --sandbox-plan
```

## Execute With a Scrubbed Install Environment

```sh
npm-gate install axios --sandbox-execute
```

Sandbox execution still runs the package manager, but only after policy allows the target. It removes common publish tokens, GitHub tokens, cloud credentials, and SSH agent variables; uses an isolated temporary home; and appends `--ignore-scripts`. npm-gate reports that network allowlisting is not enforced by this mode.

## Emergency Lockfile Rescan

```sh
npm-gate emergency --json > npm-gate-emergency-report.json
```

## Add an Allowlist Entry

```sh
npm-gate allow lodash@^4.17.21 --reason "Approved base dependency SEC-42" --expires-at 2026-06-30T00:00:00.000Z
```

Package allowlists approve package-name policy only. They do not authorize lifecycle script execution.

## Add a Lifecycle Script Allowlist Entry

Create `.npm-gate/script-allowlist.json`:

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
      "justification": "Reviewed native install script in SEC-42"
    }
  ]
}
```

The package name, exact version, script name, command hash, justification, and registry integrity must match when integrity evidence is available. Expired entries and package-name-only entries do not authorize execution.

## Explain a Package

```sh
npm-gate policy explain react@18.3.1
```

## Explain a Finding

```sh
npm-gate explain workflow-cache-poisoning-risk:.github/workflows/release.yml
```

## Generate a Report

```sh
npm-gate report --format json > npm-gate-report.json
```

## JSON Finding Shape

```json
{
  "package": "fixture",
  "version": "1.0.1",
  "decision": "block",
  "riskCategory": "lifecycle_script_risk",
  "matchedSignals": ["lifecycle-script", "lifecycle-install-downloader"],
  "evidenceSummary": "postinstall downloads remote code",
  "recommendedFix": "Remove the lifecycle script or review the artifact before installing",
  "policyMode": "strict",
  "allowlist": { "used": false },
  "dependencyPath": ["root@1.0.0", "fixture@1.0.1"]
}
```

The original JSON fields remain present. The additional fields are additive for CI consumers that want policy-mode and kill-chain context.

## Configure Source Verification

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

Source verification is optional and package-scoped. When enabled, the default verifier queries GitHub tag, commit, and configured `package.json` metadata; it does not make provenance or trusted publishing a safety bypass.

## Configure Trusted Publishing Expectations

```json
{
  "highImpactPackageNames": ["@company/core"],
  "requireTrustedPublishingForHighImpactPackages": true,
  "trustedPublishing": [
    {
      "package": "@company/core",
      "repository": "company/core",
      "workflow": ".github/workflows/publish.yml",
      "issuer": "https://token.actions.githubusercontent.com"
    }
  ]
}
```

Trusted publishing is treated as publish-path evidence. Missing or mismatched evidence fails strict and production gates for configured high-impact packages, but it does not bypass artifact, lifecycle script, dependency, frontend runtime, or CI trust-boundary checks.

## Require Cryptographic Signature Verification

```json
{
  "verifyRegistrySignatures": true,
  "requireCryptographicSignatureVerification": true
}
```

The default verifier runs `npm audit signatures --json` when verification is explicitly enabled. Required verification failures produce high-severity provenance-risk findings; verified signatures and attestations never suppress other package or workflow risks.

## Generate Enriched SARIF

```sh
npm-gate ci --sarif > npm-gate.sarif
npm-gate report --format sarif > npm-gate.sarif
```

SARIF result properties include risk category, policy mode, matched signals, dependency path, allowlist state, and kill-chain context for CI systems that consume structured metadata.
