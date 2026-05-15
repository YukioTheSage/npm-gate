# Threat Model

## Threats Addressed

- Typosquatting.
- Package confusion.
- Compromised maintainer account.
- Compromised npm publish token.
- Authenticated malicious publish from a legitimate package owner.
- Trojanized patch release.
- Malicious lifecycle scripts.
- Hidden dependency insertion.
- Manifest-only malicious publish where `package.json` changes but source repository content does not.
- Malicious dependency added in patch or minor releases.
- CI cache poisoning.
- Unsafe GitHub Actions trust boundaries.
- OIDC or trusted-publishing abuse.
- Unsafe local tarball or directory install sources.
- Unsafe configured-registry direct tarball install sources.
- CI compromise indicators.
- Missing provenance or signature anomalies.
- Credential harvesting and install-time downloader indicators in package tarballs.
- Worm-like package propagation through install scripts and package-manager recursion.
- Malicious frontend payloads targeting wallets, clipboard, transactions, DOM, fetch/XHR/WebSocket, or CDN `latest` consumption.

## Threats Not Fully Addressed

- A legitimate package intentionally turning malicious after approval.
- Malicious code that only activates at application runtime.
- A compromised CI runner that can bypass the wrapper.
- Advisories not yet published.
- Direct Git and GitHub source contents, which are gated but not cloned or inspected.
- Direct remote tarball contents from arbitrary hosts, which are blocked until remote-source trust policy is designed.
- Sophisticated obfuscation beyond static heuristics.
- Complete runtime detection of browser or application logic that does not match static indicators.
- Live incident feeds. Emergency denylist data must come from local policy config.

## Boundaries

npm-gate performs static analysis and policy enforcement. It does not execute package code, does not run live detonation, and does not scan third-party infrastructure.

## Security Principles

- Resolve safely, inspect artifacts, evaluate release path, block risky execution, sandbox only approved execution, protect credentials, and continuously rescan lockfiles and CI.
- Do not treat package popularity, legitimate maintainer identity, npm provenance, trusted publishing, semver patch status, or a valid registry publish as sufficient evidence of safety.
- Provenance proves publish path, not package safety.
- Hidden transitive dependencies must be evaluated and reported with dependency paths when available.
- High-confidence install-time execution risk should fail closed in strict and emergency modes.
