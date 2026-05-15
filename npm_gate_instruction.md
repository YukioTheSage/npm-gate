You are Codex, acting as a principal open-source software engineer, security architect, and maintainer.

Build a complete production-grade open-source repository in one pass.

Project name:
npm-gate

Project type:
Defensive npm supply-chain security system, CLI wrapper, policy engine, and local scanner.

Primary goal:
Create an open-source tool that protects developers and CI systems from malicious npm package installs by intercepting npm-like commands, evaluating dependency risk before install, enforcing policy, and producing auditable evidence.

This must be defensive-only. Do not implement malware, credential theft, exploit payloads, exfiltration code, offensive scanning of third-party systems, or live attack simulation. Any examples of malicious behavior must be inert, synthetic fixtures used only for tests.

Core idea:
npm-gate should feel like npm, but safer.

Example commands:

- npm-gate install
- npm-gate install axios
- npm-gate add lodash
- npm-gate ci
- npm-gate audit
- npm-gate scan
- npm-gate policy init
- npm-gate policy explain <package>
- npm-gate doctor
- npm-gate report --format json
- npm-gate allow <package>@<version> --reason "ticket or justification"
- npm-gate config show

The tool should be usable as:

- A direct CLI.
- An npm wrapper through aliases.
- A CI dependency gate.
- A local dependency scanner.
- A policy engine for private registry ingress.

Technical stack:
Use TypeScript on Node.js.

Use:

- Node.js >= 20.
- TypeScript.
- pnpm as the package manager for this repository.
- Commander or Clipanion for CLI parsing.
- Zod for config/schema validation.
- pacote or npm-registry-fetch for npm registry metadata.
- pacote/tar extraction or equivalent safe package tarball inspection.
- semver for version handling.
- fast-glob for file discovery.
- picocolors or chalk for terminal output.
- pino or a lightweight logger.
- vitest for tests.
- tsup or esbuild for builds.
- ESLint.
- Prettier.
- GitHub Actions CI.
- Apache-2.0 license unless a more appropriate permissive license is needed.

Repository requirements:
Create a full repository, not snippets.

Required files:

- package.json
- pnpm-lock.yaml if generated
- tsconfig.json
- tsup.config.ts or equivalent build config
- eslint config
- prettier config
- vitest config
- README.md
- CONTRIBUTING.md
- SECURITY.md
- CODE_OF_CONDUCT.md
- LICENSE
- .gitignore
- .github/workflows/ci.yml
- .github/dependabot.yml
- docs/architecture.md
- docs/threat-model.md
- docs/policy.md
- docs/ci-usage.md
- docs/incident-response.md
- docs/examples.md
- examples/basic-project/package.json
- examples/ci-gate/github-actions.yml
- src directory with clean modular code
- tests directory with unit and integration-style tests using mocked registry responses and safe local fixtures

Architecture:
Implement the project as modular components.

Suggested source layout:
src/
cli/
index.ts
commands/
install.ts
scan.ts
audit.ts
policy.ts
allow.ts
doctor.ts
report.ts
core/
engine.ts
decision.ts
risk-score.ts
types.ts
config/
config-loader.ts
default-policy.ts
schema.ts
registry/
client.ts
metadata.ts
tarball.ts
analyzers/
manifest-analyzer.ts
lifecycle-script-analyzer.ts
release-age-analyzer.ts
provenance-analyzer.ts
signature-analyzer.ts
lockfile-analyzer.ts
dependency-diff-analyzer.ts
name-confusion-analyzer.ts
tarball-static-analyzer.ts
advisory-analyzer.ts
behavior-rules.ts
policy/
policy-engine.ts
allowlist.ts
exceptions.ts
severity.ts
wrappers/
npm-runner.ts
command-classifier.ts
reporting/
console-reporter.ts
json-reporter.ts
sarif-reporter.ts
sandbox/
sandbox-plan.ts
sandbox-runner.ts
utils/
fs.ts
exec.ts
hashing.ts
package-ref.ts
time.ts
errors.ts
tests/
fixtures/
unit/
integration/

Functional requirements:

1. CLI wrapper behavior
   The tool must accept common npm-style commands and arguments.

For install-like commands:

- Parse requested packages.
- Read the current package.json and lockfile if present.
- Resolve candidate package versions through npm registry metadata.
- Evaluate risk before delegating to npm.
- If policy says allow, execute the real npm command.
- If policy says warn, print warning and allow by default unless --strict is set.
- If policy says block, do not execute npm.
- Support --dry-run to evaluate without installing.
- Support --json to output machine-readable results.
- Support --strict to turn warnings into blocks.
- Support --no-execute to never run npm even if allowed.
- Support environment variable NPM_GATE_MODE=off|warn|block|ci.

2. Scanner behavior
   Implement npm-gate scan.

It should:

- Scan package.json.
- Scan package-lock.json if present.
- Scan npm-shrinkwrap.json if present.
- Scan pnpm-lock.yaml and yarn.lock if feasible; implement at least basic package-name extraction for pnpm and yarn, even if not perfect.
- Identify dependencies, devDependencies, peerDependencies, optionalDependencies, bundledDependencies.
- Evaluate installed or locked packages against policy.
- Produce console and JSON reports.
- Return nonzero exit code for blocked findings in CI mode.

3. Policy engine
   Implement a configurable policy system.

Default config file:
npm-gate.config.json

Also support:

- npm-gate.config.yaml if YAML support is easy; otherwise document JSON-only.
- Config search from current directory upward.
- Environment overrides.

Default policy:

- minimumReleaseAgeHours: 72
- blockLifecycleScripts: true for first-seen packages or new lifecycle hooks
- warnLifecycleScripts: true for known packages
- blockGitDependencies: true in CI
- warnGitDependencies: true locally
- requireProvenanceForHighImpactPackages: false by default, configurable
- warnMissingProvenanceWhenPreviouslyPresent: true
- warnMissingRegistrySignature: true when signature data is available
- blockNewPackageNamesInCI: true unless allowlisted
- blockSuspiciousNameConfusion: true
- blockKnownMaliciousAdvisories: true
- warnUnknownPackages: true
- maxRiskScoreAllowed: 70
- maxRiskScoreWarn: 40
- allowOverridesWithJustification: true locally
- disallowOverridesInCI: true by default

Policy decision types:

- allow
- warn
- block

Each decision must include:

- package name
- version
- score
- severity
- reasons
- evidence
- recommended remediation
- whether an exception can override it

4. Risk scoring
   Implement deterministic risk scoring.

Risk signals should include:

- Very new release.
- New lifecycle scripts.
- Any preinstall, install, postinstall, prepare, prepack, postpack scripts.
- Git URL dependencies.
- Package tarball contains hidden directories such as .github, .vscode, .claude, unusual dotfiles, or executable binaries.
- Suspicious files in package tarball such as .exe, .dll, .so, .dylib, ELF files, shell scripts, PowerShell scripts, large minified blobs.
- package.json metadata changes compared with previous version.
- Newly added dependency in a patch release.
- Version published without obvious source repository metadata.
- Name similarity to a known dependency or configured protected package name.
- Missing provenance when policy requires it.
- Missing signature data when available.
- Known malicious or vulnerable advisory match.
- Package younger than policy minimum release age.
- Package has very low version history, suspicious rapid version churn, or recent owner/maintainer anomalies if metadata is available.
- Optional dependency to a GitHub branch or commit.
- Registry metadata inconsistency.
- Package name absent from allowlist in CI.

Scoring should be transparent and documented.

5. Registry metadata
   Implement a registry client that:

- Reads registry URL from npm config where practical, or defaults to https://registry.npmjs.org.
- Fetches package metadata.
- Handles scoped packages correctly.
- Handles dist-tags.
- Resolves ranges to versions.
- Caches metadata locally under .npm-gate/cache or OS cache directory.
- Supports offline mode using cache.
- Has robust timeout and retry behavior.
- Never sends secrets.
- Redacts tokens from logs.

6. Tarball static inspection
   Implement safe tarball inspection:

- Fetch package tarball metadata.
- Optionally download package tarball to a temporary directory.
- Extract safely with path traversal protection.
- Do not execute package code.
- Inspect package.json.
- Inspect filenames.
- Detect lifecycle scripts.
- Detect suspicious binary extensions.
- Detect shell or PowerShell scripts.
- Detect hidden directories.
- Detect high-entropy or very large minified JavaScript files with simple heuristics.
- Hash inspected tarball and include SHA-256 in evidence.

This must be static analysis only. Do not run install scripts.

7. Manifest diffing
   Implement comparison against previous version:

- Given package@version, find nearest previous semver version.
- Compare package.json fields:
  - scripts
  - dependencies
  - optionalDependencies
  - peerDependencies
  - devDependencies
  - bin
  - exports
  - main
  - files
  - repository
- Flag newly introduced lifecycle hooks.
- Flag newly introduced dependency names.
- Flag package switching from registry dependency to git dependency.
- Flag manifest-only suspicious changes.

8. Provenance and signature checks
   Implement best-effort checks.

Do not overclaim:

- If npm provenance/signature data is unavailable through the implemented registry path, report status as unknown.
- If available, verify or record the metadata.
- The tool should distinguish:
  - verified
  - present-unverified
  - missing
  - unavailable
  - unknown

Design the API so future proper verification can be added.

9. Advisory integration
   Implement advisory checks in a safe, dependency-light way:

- Support npm audit JSON if available by invoking npm audit --json only when scanning a local project.
- Parse audit results and map advisories to packages.
- Allow optional local advisory feed file:
  npm-gate-advisories.json
- The local advisory file should support malicious package records:
  {
  "packages": [
  {
  "name": "example",
  "versions": ["1.2.3"],
  "type": "malicious",
  "severity": "critical",
  "summary": "Synthetic test fixture only"
  }
  ]
  }

10. Name confusion detection
    Implement simple defensive heuristics:

- Levenshtein distance against protected package names.
- Confusable separator normalization:
  lodash-es vs lodash_es vs lodashes
  react-router vs reactrouter
- Scope confusion:
  @company/pkg vs company-pkg
- Warn/block if a new package name is very similar to an allowlisted or protected dependency.
- Include explanation and confidence.
- Allow users to configure protected names.

11. Exceptions and allowlist
    Implement:

- .npm-gate/allowlist.json
- .npm-gate/exceptions.json

Allowlist entries:

- package
- version or semver range
- reason
- addedBy
- addedAt
- expiresAt optional
- ticket optional

Exceptions:

- finding ID
- package
- version
- reason
- expiresAt
- createdAt

CLI:

- npm-gate allow <package>@<version> --reason "..."`
- npm-gate allow <package>@<range> --reason "..."`
- npm-gate policy explain <package>@<version>

Never silently ignore a finding. If an exception suppresses it, report it as suppressed with evidence.

12. Reports
    Implement:

- Human-readable console report.
- JSON report.
- SARIF report if feasible.

The report should include:

- Summary counts by allow/warn/block.
- Package findings.
- Risk score.
- Reasons.
- Evidence.
- Policy path.
- Config source.
- Runtime mode.
- Timestamp.
- Tool version.
- Suggested remediation.

13. CI mode
    CI behavior:

- NPM_GATE_MODE=ci should fail on block.
- --strict should fail on warn and block.
- Provide GitHub Actions example.
- Use exit code 0 for clean allow/warn in non-strict local mode.
- Use exit code 1 for block.
- Use exit code 2 for internal tool error.
- Use exit code 3 for policy/config error.

14. Sandbox design
    Implement a sandbox module as a safe placeholder:

- Do not execute untrusted package code by default.
- Provide a SandboxPlan object describing what would be analyzed.
- Provide documentation for future isolated container-based detonation.
- Provide a --sandbox-plan flag that outputs the plan.
- Do not implement live detonation unless it is completely inert and isolated.
- The purpose is to keep this repository safe and defensible.

15. Security requirements

- Never log npm tokens.
- Redact tokens from .npmrc, URLs, env vars, and command output.
- Do not read credential files except to redact known config paths when needed.
- Do not access cloud metadata services.
- Do not make outbound network calls except npm registry metadata/tarball fetches explicitly required for package analysis.
- Do not run package lifecycle scripts during analysis.
- Do not execute code from packages.
- Protect tar extraction against path traversal.
- Validate all config with Zod.
- Include tests for redaction, tar traversal protection, lifecycle detection, name confusion detection, and policy decisions.

16. Documentation
    README.md must include:

- What npm-gate is.
- Why dependency installation is code execution.
- Installation.
- Quick start.
- CLI examples.
- Local developer usage.
- CI usage.
- Config example.
- Policy example.
- Report example.
- Limitations.
- Security model.
- Contribution guide summary.
- License.

docs/threat-model.md must include:

- Threats addressed:
  - typosquatting
  - package confusion
  - compromised maintainer account
  - trojanized patch release
  - malicious lifecycle scripts
  - hidden dependency insertion
  - CI compromise indicators
  - missing provenance or signature anomalies
- Threats not fully addressed:
  - legitimate package intentionally turning malicious after approval
  - malicious code that only activates at application runtime
  - compromised CI runner that can bypass the wrapper
  - advisories not yet published
  - sophisticated obfuscation beyond static heuristics

docs/incident-response.md must include:

- What to preserve:
  - package-lock.json
  - npm-shrinkwrap.json
  - pnpm-lock.yaml
  - yarn.lock
  - package tarballs
  - npm cache
  - CI logs
  - registry proxy logs
  - GitHub Actions logs
  - credential rotation timestamps
- What to do after suspected malicious install:
  - isolate host or runner
  - rotate reachable credentials
  - search lockfiles
  - purge private registry cache
  - review update bot PRs
  - audit GitHub/npm token usage

17. Tests
    Create meaningful tests.

Minimum test coverage:

- Config loading and validation.
- Package reference parsing:
  - lodash
  - lodash@latest
  - @scope/pkg
  - @scope/pkg@1.2.3
  - file dependencies
  - git dependencies
- Risk scoring.
- Lifecycle script detection.
- Manifest diff detection.
- Name confusion detection.
- Advisory file parsing.
- Allowlist and exception suppression.
- JSON report shape.
- Token redaction.
- Safe tar extraction path traversal rejection.
- CLI scan on fixture projects.
- Policy decision allow/warn/block.

Use mocked registry responses. Tests must not depend on live internet.

18. Fixtures
    Create safe synthetic fixture packages:

- clean-package
- package-with-postinstall
- package-with-new-preinstall
- package-with-hidden-dotdir
- package-with-binary-file
- package-with-git-dependency
- package-with-new-dependency-in-patch
- typosquat-like-package
- advisory-malicious-package

All fixtures must be inert and must not contain harmful code.

19. Build and quality
    The repository must support:

- pnpm install
- pnpm build
- pnpm test
- pnpm lint
- pnpm format
- pnpm typecheck

package.json scripts:

- build
- dev
- test
- test:watch
- lint
- format
- typecheck
- clean

20. GitHub Actions
    Create CI workflow:

- Checkout.
- Setup Node 20 and 22 matrix if reasonable.
- Setup pnpm.
- Install dependencies.
- Run typecheck.
- Run lint.
- Run tests.
- Run build.

21. Dependabot
    Add Dependabot config for:

- npm dependencies.
- GitHub Actions.

22. Open-source readiness
    Add:

- CONTRIBUTING.md with development setup and contribution standards.
- SECURITY.md with vulnerability reporting instructions.
- CODE_OF_CONDUCT.md.
- Apache-2.0 LICENSE.
- Clear package metadata in package.json.
- Bin entry for npm-gate.

23. Implementation depth
    Do not produce placeholders where real code is practical.

Implement working versions of:

- CLI.
- Config loader.
- Policy engine.
- Risk scorer.
- Registry client with mockable interface.
- Static tarball analyzer.
- Manifest analyzer.
- Lifecycle analyzer.
- Name confusion analyzer.
- Advisory parser.
- Allowlist/exception manager.
- Console and JSON reporters.
- npm command delegation.
- Tests.

Acceptable stubs:

- Full cryptographic provenance verification can be a structured best-effort interface with documented unknown/unavailable states.
- Full sandbox detonation should remain a safe non-executing plan by default.
- SARIF can be basic but valid, or omitted only if clearly documented.

24. UX requirements
    Console output should be clear and actionable.

Example blocked output:
BLOCKED: axios@1.14.1
Risk score: 92 critical
Reasons:

- Release is newer than minimum policy age of 72h.
- New install-time lifecycle script detected.
- New dependency added in patch release.
- Package metadata differs suspiciously from previous version.
  Recommended actions:
- Pin previous known-good version.
- Review package tarball and upstream repository.
- Wait for release-age cooldown.
- Require security approval to override.

25. Safety requirements for Codex
    While building:

- Do not fetch or run unknown packages unless necessary for project dependency installation.
- Do not add dependencies that are unnecessary.
- Prefer small, auditable dependency set.
- Do not include real IoCs as executable examples.
- Do not include exploit payloads.
- Do not include credential-harvesting code.
- Do not include commands that read ~/.ssh, ~/.npmrc, cloud metadata endpoints, or other secrets.
- Redaction tests may use synthetic strings only.

26. Final response after implementation
    After creating the repository, provide:

- Summary of what was built.
- File tree.
- Key features.
- Commands to run.
- Tests status.
- Known limitations.
- Any assumptions made.

Now build the full repository.
