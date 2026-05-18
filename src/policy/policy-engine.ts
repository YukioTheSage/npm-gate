import type {
  PackageCandidate,
  PackageFinding,
  PolicyConfig,
  PolicyMode,
  RiskCategory,
  RiskSignal,
  RuntimeMode
} from '../core/types.js';
import { scoreSignals } from '../core/risk-score.js';

export interface DecidePackageInput {
  candidate: PackageCandidate;
  policy: PolicyConfig;
  mode: RuntimeMode;
  policyMode?: PolicyMode;
  signals: RiskSignal[];
  strict?: boolean;
  allowlisted?: boolean;
  allowlist?: PackageFinding['allowlist'];
}

function categoryForSignal(signal: RiskSignal): RiskCategory | undefined {
  if (signal.riskCategory) return signal.riskCategory;
  if (signal.id.includes('lifecycle')) return 'lifecycle_script_risk';
  if (signal.id.includes('dependency')) return 'dependency_delta_risk';
  if (signal.id.includes('tarball') || signal.id.includes('manifest') || signal.id.startsWith('source-'))
    return 'artifact_diff_risk';
  if (signal.id.includes('provenance') || signal.id.includes('signature')) return 'provenance_risk';
  if (signal.id.startsWith('workflow-')) return 'ci_trust_boundary_risk';
  if (signal.id.includes('credential')) return 'credential_exposure_risk';
  if (signal.id.includes('name-confusion') || signal.id.includes('typosquat'))
    return 'typosquat_risk';
  if (
    signal.id.includes('frontend') ||
    signal.id.includes('wallet') ||
    signal.id.includes('cdn') ||
    signal.id.includes('sri')
  )
    return 'frontend_runtime_risk';
  if (signal.id.includes('emergency') || signal.id.includes('known-bad'))
    return 'emergency_denylist_risk';
  return undefined;
}

function isStrictReleaseGate(
  policy: PolicyConfig,
  mode: RuntimeMode,
  policyMode: PolicyMode
): boolean {
  return (
    mode === 'ci' ||
    policy.profile === 'production' ||
    policyMode === 'strict' ||
    policyMode === 'emergency'
  );
}

function mustBlockSignal(
  signal: RiskSignal,
  policy: PolicyConfig,
  mode: RuntimeMode,
  policyMode: PolicyMode
): boolean {
  const hardBlockSignals = new Set([
    'registry-tarball-integrity-mismatch',
    'required-intelligence-unavailable',
    'unapproved-resolved-host',
    'lockfile-integrity-changed',
    'workflow-dangerous-trigger',
    'workflow-untrusted-checkout',
    'workflow-cache-poisoning-risk',
    'workflow-overprivileged-token',
    'workflow-oidc-cache-boundary',
    'workflow-run-artifact-trust-boundary',
    'workflow-publish-after-risky-install',
    'provenance-source-mismatch',
    'unexpected-provenance-source',
    'emergency-denylist-match',
    'lifecycle-install-downloader',
    'lifecycle-powershell-downloader',
    'lifecycle-shell-pipe',
    'lifecycle-global-package-install',
    'lifecycle-chmod-exec',
    'lifecycle-package-manager-recursion',
    'lifecycle-obfuscated-payload',
    'lifecycle-native-binary-execution',
    'lifecycle-windows-native-loader',
    'lifecycle-bun-bootstrap'
  ]);
  if (policyMode === 'emergency' && signal.severity !== 'info') return true;
  const strictReleaseBlockSignals = new Set([
    'new-dependency-in-patch-release',
    'new-binary-file',
    'new-suspicious-file',
    'obfuscated-code-pattern',
    'invisible-unicode-source',
    'unsupported-remote-tarball',
    'remote-tarball-uninspectable',
    'remote-tarball-manifest-missing',
    'remote-tarball-manifest-invalid'
  ]);
  if (isStrictReleaseGate(policy, mode, policyMode) && strictReleaseBlockSignals.has(signal.id)) {
    return true;
  }
  if (
    policyMode === 'strict' &&
    [
      'frontend-runtime-wallet-access',
      'frontend-runtime-clipboard-mutation',
      'frontend-runtime-transaction-mutation'
    ].includes(signal.id)
  ) {
    return true;
  }
  if (
    (policyMode === 'strict' || policyMode === 'emergency') &&
    [
      'source-tag-missing',
      'source-commit-missing',
      'source-tag-commit-mismatch',
      'source-verification-unavailable'
    ].includes(signal.id) &&
    signal.canOverride === false
  ) {
    return true;
  }
  if (hardBlockSignals.has(signal.id)) return true;
  if (signal.id === 'known-malicious-advisory' && policy.blockKnownMaliciousAdvisories) return true;
  if (
    (signal.id === 'lifecycle-script' || signal.id === 'new-lifecycle-script') &&
    policy.blockLifecycleScripts &&
    (policyMode === 'strict' || policyMode === 'emergency' || signal.id === 'lifecycle-script')
  )
    return true;
  if (
    (signal.id === 'git-dependency' || signal.id === 'git-dependency-switch') &&
    (mode === 'ci' || policyMode === 'strict' || policyMode === 'emergency') &&
    policy.blockGitDependencies
  ) {
    return true;
  }
  if (
    signal.id === 'project-cdn-latest' &&
    (mode === 'ci' || policyMode === 'strict' || policyMode === 'emergency')
  ) {
    return true;
  }
  if (signal.id === 'name-confusion' && policy.blockSuspiciousNameConfusion) return true;
  if (signal.id === 'new-package-name-ci' && mode === 'ci' && policy.blockNewPackageNamesInCI)
    return true;
  if (
    policy.blockCredentialHarvestingPatterns &&
    (mode === 'ci' || policy.profile === 'production') &&
    (signal.id === 'credential-harvesting-pattern' ||
      signal.id === 'child-process-network-exfil' ||
      signal.id === 'process-env-network-exfil')
  ) {
    return true;
  }
  if (
    policy.blockInstallDownloaders &&
    (mode === 'ci' || policy.profile === 'production') &&
    signal.id === 'install-downloader-pattern'
  ) {
    return true;
  }
  return false;
}

function requiresManualReview(signal: RiskSignal, policyMode: PolicyMode): boolean {
  if (policyMode === 'emergency') return false;
  if (signal.manualReview) return true;
  return new Set([
    'new-dependency-in-release',
    'new-dependency-in-patch-release',
    'new-binary-file',
    'source-repository-changed',
    'frontend-runtime-wallet-access',
    'frontend-runtime-clipboard-mutation',
    'frontend-runtime-transaction-mutation',
    'project-cdn-latest',
    'project-external-script-missing-sri',
    'medium-confidence-typosquat'
  ]).has(signal.id);
}

function remediation(signals: RiskSignal[]): string[] {
  const values = signals.flatMap((signal) => signal.remediation ?? []);
  return values.length > 0
    ? [...new Set(values)]
    : ['No action required.', 'For warnings, review package metadata and pin known-good versions.'];
}

function incidentResponseRemediation(decision: PackageFinding['decision']): string[] {
  return decision === 'block'
    ? [
        'Do not install or release until this finding is resolved.',
        'If this package or workflow already ran on a sensitive host, rotate reachable credentials and review install or CI logs.'
      ]
    : [];
}

function isActionableSignal(signal: RiskSignal): boolean {
  return signal.severity !== 'info' || signal.score > 0;
}

export function decidePackage(input: DecidePackageInput): PackageFinding {
  const {
    candidate,
    policy,
    mode,
    signals,
    strict = false,
    allowlisted = false,
    allowlist,
    policyMode = policy.policyMode
  } = input;
  const effectiveSignals = allowlisted
    ? signals.filter((signal) => signal.id !== 'new-package-name-ci')
    : signals;
  const actionableSignals = effectiveSignals.filter(isActionableSignal);
  const scored = scoreSignals(effectiveSignals);
  const mustBlock = actionableSignals.some((signal) =>
    mustBlockSignal(signal, policy, mode, policyMode)
  );
  const mustManualReview = actionableSignals.some((signal) =>
    requiresManualReview(signal, policyMode)
  );
  const hasWarn = actionableSignals.length > 0 || scored.score >= policy.maxRiskScoreWarn;
  let decision: PackageFinding['decision'] = 'allow';

  if (mode === 'off') {
    decision = 'allow';
  } else if (mustBlock || scored.score >= policy.maxRiskScoreAllowed) {
    decision = 'block';
  } else if (mustManualReview) {
    decision = 'manual_review';
  } else if (hasWarn) {
    decision = mode === 'block' || strict ? 'block' : 'warn';
  }

  const recommendedActions = [
    ...remediation(actionableSignals),
    ...incidentResponseRemediation(decision)
  ];

  const matchedSignals = [
    ...new Set(actionableSignals.flatMap((signal) => [signal.id, ...(signal.matchedSignals ?? [])]))
  ];
  const firstCategory = actionableSignals.map(categoryForSignal).find(Boolean);
  const evidenceSummary = actionableSignals
    .flatMap((signal) => signal.evidence ?? [])
    .map((evidence) => evidence.message)
    .filter(Boolean)
    .slice(0, 4)
    .join('; ');
  const dependencyPath = actionableSignals.find((signal) => signal.dependencyPath)?.dependencyPath;
  const recommendedFix = recommendedActions[0] ?? 'No action required.';

  return {
    id: `${actionableSignals[0]?.id ?? 'clean'}:${candidate.name}@${candidate.version ?? candidate.spec ?? 'unknown'}`,
    package: candidate.name,
    version: candidate.version,
    decision,
    severity: scored.severity,
    score: scored.score,
    reasons:
      actionableSignals.length > 0
        ? actionableSignals.map((signal) => signal.message)
        : ['No policy issues detected'],
    evidence: effectiveSignals.flatMap((signal) => signal.evidence ?? []),
    remediation: [...new Set(recommendedActions)],
    riskCategory: firstCategory,
    matchedSignals,
    evidenceSummary,
    recommendedFix,
    policyMode,
    dependencyPath,
    killChain:
      decision === 'block'
        ? `Blocked: ${candidate.name}${candidate.version ? `@${candidate.version}` : ''} matched ${matchedSignals.join(', ') || 'policy'} risk. ${actionableSignals[0]?.message ?? 'Policy blocked this target.'}`
        : undefined,
    allowlist: allowlist ?? (allowlisted ? { used: true, scope: 'package' } : { used: false }),
    canOverride:
      decision !== 'allow' &&
      policy.allowOverridesWithJustification &&
      !(mode === 'ci' && policy.disallowOverridesInCI) &&
      actionableSignals.every((signal) => signal.canOverride !== false)
  };
}
