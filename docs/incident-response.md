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

## Emergency Mode

Emergency mode is local and deterministic. It does not pull live incident feeds. Add known-bad package versions to `npm-gate.config.json`:

```json
{
  "policyMode": "emergency",
  "emergencyDenylist": [
    {
      "package": "compromised-package",
      "versions": ["1.2.3", "1.2.4"],
      "reason": "Confirmed malicious publish SEC-2026-001"
    }
  ]
}
```

Then rescan lockfiles and workflow configuration:

```sh
npm-gate emergency --json > npm-gate-emergency-report.json
```

The report lists affected direct and transitive packages, affected versions, dependency paths when available, and block decisions. The console output also prints credential-rotation and CI-cleanup checklists.

## Credential Rotation Checklist

- Rotate npm automation tokens and publish tokens.
- Rotate GitHub tokens, deploy keys, and fine-grained PATs reachable from affected machines or CI.
- Rotate cloud credentials and OIDC trust bindings exposed to the affected workflow.
- Rotate SSH keys and invalidate active SSH agent sessions.
- Revoke package registry sessions used during the likely exposure window.

## CI Cleanup Checklist

- Clear npm, pnpm, yarn, and build caches that could have been written by PR or untrusted jobs.
- Review GitHub Actions workflow changes for malicious persistence.
- Check release workflows for new `pull_request_target`, `workflow_run`, cache, and OIDC trust-boundary changes.
- Inspect release logs for unexpected `npm publish`, token minting, downloader, or lifecycle-script execution.
- Check npm package ownership, maintainer additions, access tokens, and unauthorized publishes.
- Rebuild release artifacts from a clean runner with lifecycle scripts disabled until the package set is reviewed.
