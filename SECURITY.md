# Security Policy

## Reporting Vulnerabilities

Report suspected vulnerabilities privately to the maintainers through the repository security advisory flow or the configured project security contact. Do not open public issues with working exploit details.

Include:

- Affected version or commit.
- Clear reproduction steps using synthetic data.
- Expected and actual behavior.
- Whether npm tokens, registry credentials, or CI secrets could be exposed.

## Scope

In scope:

- Token redaction failures.
- Unsafe tar extraction.
- Package code execution during analysis.
- Policy bypasses.
- Incorrect CI exit behavior.

Out of scope:

- Requests to add offensive payloads.
- Live malware analysis or detonation.
- Attacks against third-party npm packages or registries.
