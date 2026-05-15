# Threat Model

## Threats Addressed

- Typosquatting.
- Package confusion.
- Compromised maintainer account.
- Trojanized patch release.
- Malicious lifecycle scripts.
- Hidden dependency insertion.
- Unsafe local tarball or directory install sources.
- Unsafe configured-registry direct tarball install sources.
- CI compromise indicators.
- Missing provenance or signature anomalies.
- Credential harvesting and install-time downloader indicators in package tarballs.

## Threats Not Fully Addressed

- A legitimate package intentionally turning malicious after approval.
- Malicious code that only activates at application runtime.
- A compromised CI runner that can bypass the wrapper.
- Advisories not yet published.
- Direct Git and GitHub source contents, which are gated but not cloned or inspected.
- Direct remote tarball contents from arbitrary hosts, which are blocked until remote-source trust policy is designed.
- Sophisticated obfuscation beyond static heuristics.
- Complete runtime detection of browser or application logic that does not match static indicators.

## Boundaries

npm-gate performs static analysis and policy enforcement. It does not execute package code, does not run live detonation, and does not scan third-party infrastructure.
