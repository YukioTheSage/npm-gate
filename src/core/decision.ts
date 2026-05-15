import type { DecisionKind, PackageFinding, ScanReport } from './types.js';

export function shouldFail(decision: DecisionKind, strict = false): boolean {
  return decision === 'block' || (strict && (decision === 'warn' || decision === 'manual_review'));
}

export function effectiveDecision(finding: PackageFinding): DecisionKind {
  return finding.suppressed ? 'allow' : finding.decision;
}

export function exitCodeForFindings(findings: PackageFinding[], strict = false): number {
  return findings.some((finding) => !finding.suppressed && shouldFail(finding.decision, strict))
    ? 1
    : 0;
}

export function strictExitForReport(
  report: Pick<ScanReport, 'policyMode'>,
  strict = false
): boolean {
  return strict || report.policyMode === 'strict' || report.policyMode === 'emergency';
}
