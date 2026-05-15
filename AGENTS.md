# AGENTS.md

This repository is npm-gate, an npm supply-chain security CLI.

## Security Rules For Agents

- Do not add production dependencies without a clear security or maintenance justification.
- Do not run `npm install`, `pnpm install`, `yarn install`, or package-manager commands with lifecycle scripts enabled unless the user explicitly requires it.
- Do not expose secrets, tokens, environment variable values, or credential file contents in logs, tests, docs, or reports.
- Preserve JSON output compatibility. Add fields only when possible and keep existing fields stable.
- Add tests for every security rule or analyzer behavior change.
- Prefer fail-closed behavior for high-confidence execution risk.
- Treat provenance and trusted publishing as signals, not safety bypasses.
- Keep malicious fixtures synthetic, inert, and non-executing.
- Do not broaden lifecycle script allowlists into package-name-only rules.
- Do not let trusted publishing bypass artifact, lifecycle script, dependency, frontend runtime, or CI trust-boundary checks.
- Do not implement behavior that downloads and executes remote code during analysis or tests.
- Prefer local mocked registry, tarball, workflow, and lockfile fixtures over live npm or GitHub access in tests.

## Verification Expectations

Before reporting implementation work complete, run the relevant subset of:

```sh
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm smoke:pack
```

Report any failures with the command, exit code, and whether the failure is related to the current change.
