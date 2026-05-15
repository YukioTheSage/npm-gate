import type {
  PackageCandidate,
  PackageFinding,
  PolicyConfig,
  RiskSignal,
  RuntimeMode
} from '../core/types.js';
import { scoreSignals } from '../core/risk-score.js';

export interface DecidePackageInput {
  candidate: PackageCandidate;
  policy: PolicyConfig;
  mode: RuntimeMode;
  signals: RiskSignal[];
  strict?: boolean;
  allowlisted?: boolean;
}

function mustBlockSignal(signal: RiskSignal, policy: PolicyConfig, mode: RuntimeMode): boolean {
  const hardBlockSignals = new Set([
    'registry-tarball-integrity-mismatch',
    'required-intelligence-unavailable',
    'unapproved-resolved-host',
    'lockfile-integrity-changed',
    'workflow-dangerous-trigger',
    'workflow-untrusted-checkout',
    'workflow-cache-poisoning-risk',
    'workflow-overprivileged-token',
    'provenance-source-mismatch'
  ]);
  if (hardBlockSignals.has(signal.id)) return true;
  if (signal.id === 'known-malicious-advisory' && policy.blockKnownMaliciousAdvisories) return true;
  if (
    (signal.id === 'lifecycle-script' || signal.id === 'new-lifecycle-script') &&
    policy.blockLifecycleScripts
  )
    return true;
  if (
    (signal.id === 'git-dependency' || signal.id === 'git-dependency-switch') &&
    mode === 'ci' &&
    policy.blockGitDependencies
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
      signal.id === 'child-process-network-exfil')
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
  const { candidate, policy, mode, signals, strict = false, allowlisted = false } = input;
  const actionableSignals = signals.filter(isActionableSignal);
  const scored = scoreSignals(signals);
  const mustBlock = signals.some((signal) => mustBlockSignal(signal, policy, mode));
  const hasWarn = actionableSignals.length > 0 || scored.score >= policy.maxRiskScoreWarn;
  let decision: PackageFinding['decision'] = 'allow';

  if (mode === 'off' || allowlisted) {
    decision = 'allow';
  } else if (mustBlock || scored.score >= policy.maxRiskScoreAllowed) {
    decision = 'block';
  } else if (hasWarn) {
    decision = mode === 'block' || strict ? 'block' : 'warn';
  }

  const recommendedActions = [
    ...remediation(actionableSignals),
    ...incidentResponseRemediation(decision)
  ];

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
    evidence: signals.flatMap((signal) => signal.evidence ?? []),
    remediation: [...new Set(recommendedActions)],
    canOverride:
      decision !== 'allow' &&
      policy.allowOverridesWithJustification &&
      !(mode === 'ci' && policy.disallowOverridesInCI) &&
      actionableSignals.every((signal) => signal.canOverride !== false)
  };
}
