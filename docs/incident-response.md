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
npm-gate ci --release-audit --json > npm-gate-release-audit-report.json
```

The emergency report lists affected direct and transitive packages, affected versions, dependency paths when available, and block decisions. The release-audit report also performs deep transitive tarball inspection so hidden dependency payloads and artifact deltas are visible before a release resumes. The console output also prints credential-rotation and CI-cleanup checklists.

## Local Advisory Feed

npm-gate does not pull live incident feeds. Convert reviewed external intelligence into `npm-gate-advisories.json` at the repository root:

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

Keep advisory records specific to affected package names and versions. Malicious records block matching versions; vulnerability records remain reviewable according to severity and policy mode.

## Signed Incident Feed

For fast-moving incidents, distribute a reviewed signed snapshot and require it in release CI:

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

The feed file must use this shape:

```json
{
  "payload": {
    "packages": [
      {
        "name": "compromised-package",
        "versions": ["1.2.3"],
        "type": "malicious",
        "severity": "critical",
        "summary": "Confirmed malicious publish SEC-2026-001"
      }
    ]
  },
  "signature": "base64-ed25519-signature"
}
```

The signature is verified before any record is trusted. If `signed-feed` is listed in `requiredIntelligenceSources`, missing files, invalid keys, schema errors, and signature failures block CI as unavailable intelligence.

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
- Check application source for CDN `@latest` scripts and external script tags without SRI.
- Rebuild release artifacts from a clean runner with lifecycle scripts disabled until the package set is reviewed.
