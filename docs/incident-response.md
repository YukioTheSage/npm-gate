# Incident Response

## Preserve

- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- Package tarballs.
- npm cache.
- CI logs.
- Registry proxy logs.
- GitHub Actions logs.
- Credential rotation timestamps.

## After a Suspected Malicious Install

- Isolate the host or runner.
- Rotate reachable credentials.
- Search lockfiles for the package name and version.
- Purge private registry cache entries for the package.
- Review update bot pull requests.
- Audit GitHub and npm token usage.

Keep npm-gate JSON or SARIF reports with the preserved evidence bundle.
