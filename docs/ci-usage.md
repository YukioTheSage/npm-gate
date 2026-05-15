# CI Usage

Set `NPM_GATE_MODE=ci` to enable CI-specific blocking defaults. Prefer `npm-gate ci` for production dogfooding because it forces the production profile and runs dependency, lockfile, registry tarball, and GitHub workflow checks in one command.

```sh
NPM_GATE_MODE=ci npm-gate scan --production
NPM_GATE_MODE=ci npm-gate ci --json
```

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
- `1`: block decision, or warning under strict/production CI behavior.
- `2`: internal tool error.
- `3`: policy or config error.

See [../examples/ci-gate/github-actions.yml](../examples/ci-gate/github-actions.yml) for a GitHub Actions example.
