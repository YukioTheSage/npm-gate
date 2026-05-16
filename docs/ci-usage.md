# CI Usage

Set `NPM_GATE_MODE=ci` to enable CI-specific blocking defaults. Prefer `npm-gate ci` for production dogfooding because it forces the production profile and runs dependency, lockfile, direct registry tarball, and GitHub workflow checks in one command.

```sh
NPM_GATE_MODE=ci npm-gate scan --production
NPM_GATE_POLICY_MODE=strict npm-gate scan --production --json
NPM_GATE_MODE=ci npm-gate ci --json
NPM_GATE_MODE=ci npm-gate ci --release-audit --json
NPM_GATE_MODE=ci npm-gate ci --previous-package-lock ../baseline/package-lock.json --json
```

Default CI scans keep transitive analysis bounded for predictable runtime. Use `npm-gate ci --release-audit` for slower release or incident audits that should also fetch and inspect transitive dependency tarballs. The lower-level `--deep-tarballs` flag remains available for scripts that only need to opt into deep artifact inspection.

In bootstrap CI, install dependencies with lifecycle scripts disabled before running the local gate binary. A script-enabled `npm install`, `npm ci`, `pnpm install`, or `yarn install` before the gate is unsafe because dependency lifecycle scripts may already have executed.

```sh
pnpm install --ignore-scripts --frozen-lockfile
pnpm build
node dist/index.js ci --release-audit --json
```

If `npm-gate` is installed as a project dependency, use `pnpm exec npm-gate ci`.
For one-off CI usage, pin an approved version with
`pnpm dlx npm-gate@<approved-version> ci --json`.

The repository CI also runs `pnpm smoke:pack` after build. That smoke packs the CLI, installs the packed tarball into a temporary project, and verifies local plus configured-registry remote tarball scans without relying on live package fixtures.

`--previous-package-lock <path>` compares current `package-lock.json` integrity values against a baseline. `--previous-pnpm-lock <path>` and `--previous-yarn-lock <path>` provide the same integrity-change check for `pnpm-lock.yaml` and Yarn classic `yarn.lock`. The same baselines can be provided with `NPM_GATE_BASE_PACKAGE_LOCK`, `NPM_GATE_BASE_PNPM_LOCK`, and `NPM_GATE_BASE_YARN_LOCK`.

`NPM_GATE_MODE=off` is a local escape hatch only. `install` and `add` reject it in CI or release contexts such as `CI=true`, `GITHUB_ACTIONS=true`, or `NPM_GATE_RELEASE=true`.

Cryptographic registry signature verification is opt-in. Set `verifyRegistrySignatures` to run the configured verifier without making every failure a hard requirement. Set `requireCryptographicSignatureVerification` only in release jobs whose npm CLI and lockfile behavior have been reviewed; the default verifier runs `npm audit signatures --json` and caches the project-level result for the scan.

## Local Incident Intelligence

npm-gate does not pull live incident feeds in CI. Import reviewed external intelligence into `npm-gate-advisories.json` at the project root:

```json
{
  "packages": [
    {
      "name": "compromised-package",
      "versions": ["1.2.3", "1.2.4"],
      "type": "malicious",
      "severity": "critical",
      "summary": "Confirmed malicious publish SEC-2026-001"
    }
  ]
}
```

Malicious records block matching versions. Use `ci --release-audit` after adding incident data so direct and transitive tarballs are inspected before release.

For centrally reviewed snapshots, configure signed incident feeds instead of copying advisory JSON by hand:

```json
{
  "requiredIntelligenceSources": ["local", "signed-feed"],
  "signedIncidentFeeds": [
    {
      "path": "./security/npm-gate-incident-feed.json",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ]
}
```

Each signed feed file contains `{ "payload": { "packages": [...] }, "signature": "base64" }`. The signature is verified over the canonical `JSON.stringify(payload)` bytes before any advisory is trusted. When `signed-feed` is required, missing files, invalid keys, schema errors, and signature failures block CI as unavailable intelligence.

Exit codes:

- `0`: clean allow or non-strict local warning.
- `1`: block decision, manual review under strict or emergency policy, or warning under strict/production CI behavior.
- `2`: internal tool error.
- `3`: policy or config error.

## GitHub Actions Trust Boundaries

The CI scanner checks `.github/workflows/*.yml` and `.github/workflows/*.yaml` for release trust-boundary risks:

- `pull_request_target` workflows that checkout or execute untrusted PR code.
- `workflow_run` workflows that consume artifacts from untrusted workflows.
- OIDC token minting combined with package-manager cache restore.
- Package-manager cache use in privileged workflows or when release caches are forbidden.
- Broad permissions such as `contents: write`, `packages: write`, `actions: write`, or `id-token: write`.
- External actions not pinned to full commit SHA.
- Self-hosted runners on untrusted PR workflows.
- `npm publish` or `pnpm publish` after `npm`, `pnpm`, or `yarn` install commands that omit `--ignore-scripts`.

Strict exit semantics fail emitted workflow warnings and hard-block unsafe OIDC, cache, `workflow_run` artifact, publish-after-risky-install, overprivileged token, and `pull_request_target` combinations. Emergency mode blocks every emitted workflow risk.

## Safer Install Context

Run dependency installation and npm-gate analysis with no npm tokens, no SSH agent, no cloud credentials, no browser profile or wallet access, no writable home directory where possible, and no broad network egress. npm-gate reports credential categories only and never prints secret values.

For local recovery or review workflows that still need package-manager delegation, use `npm-gate install --sandbox-execute`. It removes common secret-bearing environment variables, uses a temporary home, and appends `--ignore-scripts`; it does not enforce network allowlisting or OS-level containment. CI release jobs should still prefer explicit `pnpm install --ignore-scripts --frozen-lockfile` bootstrap before `npm-gate ci --release-audit`.

See [../examples/ci-gate/github-actions.yml](../examples/ci-gate/github-actions.yml) for a GitHub Actions example.
