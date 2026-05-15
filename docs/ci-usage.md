# CI Usage

Set `NPM_GATE_MODE=ci` to enable CI-specific blocking defaults. Prefer `npm-gate ci` for production dogfooding because it forces the production profile and runs dependency, lockfile, direct registry tarball, and GitHub workflow checks in one command.

```sh
NPM_GATE_MODE=ci npm-gate scan --production
NPM_GATE_POLICY_MODE=strict npm-gate scan --production --json
NPM_GATE_MODE=ci npm-gate ci --json
```

Default CI scans keep transitive analysis bounded for predictable runtime. Use `npm-gate ci --deep-tarballs` only for slower release audits that should also fetch and inspect transitive dependency tarballs.

In bootstrap CI, install dependencies with lifecycle scripts disabled before running the local gate binary:

```sh
pnpm install --ignore-scripts --frozen-lockfile
pnpm build
node dist/index.js doctor
```

If `npm-gate` is installed as a project dependency, use `pnpm exec npm-gate ci`.
For one-off CI usage, pin an approved version with
`pnpm dlx npm-gate@<approved-version> ci --json`.

The repository CI also runs `pnpm smoke:pack` after build. That smoke packs the CLI, installs the packed tarball into a temporary project, and verifies local plus configured-registry remote tarball scans without relying on live package fixtures.

Exit codes:

- `0`: clean allow or non-strict local warning.
- `1`: block decision, manual review under strict or emergency policy, or warning under strict/production CI behavior.
- `2`: internal tool error.
- `3`: policy or config error.

## GitHub Actions Trust Boundaries

The CI scanner checks `.github/workflows/*.yml` and `.github/workflows/*.yaml` for release trust-boundary risks:

- `pull_request_target` workflows that checkout or execute untrusted PR code.
- `workflow_run` workflows that consume artifacts from untrusted workflows.
- Release jobs with `id-token: write` after cache restore or risky install/build/test steps.
- Package-manager caches shared between PR and release jobs.
- Broad permissions such as `contents: write`, `packages: write`, `actions: write`, or `id-token: write`.
- Third-party actions not pinned to full commit SHA.
- Secrets available to build/test jobs.
- Self-hosted runners on untrusted PR workflows.
- `npm publish` after risky install or cache restore.
- Release jobs running `npm install` or `npm ci` without `--ignore-scripts`.

Strict mode blocks unsafe OIDC, cache, and `pull_request_target` combinations. Emergency mode blocks release workflows with shared cache plus `id-token: write`.

## Safer Install Context

Run dependency installation and npm-gate analysis with no npm tokens, no SSH agent, no cloud credentials, no browser profile or wallet access, no writable home directory where possible, and no broad network egress. npm-gate reports credential categories only and never prints secret values.

See [../examples/ci-gate/github-actions.yml](../examples/ci-gate/github-actions.yml) for a GitHub Actions example.
