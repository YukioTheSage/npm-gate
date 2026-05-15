import type { DecisionKind, PackageFinding } from './types.js';

export function shouldFail(decision: DecisionKind, strict = false): boolean {
  return decision === 'block' || (strict && decision === 'warn');
}

export function effectiveDecision(finding: PackageFinding): DecisionKind {
  return finding.suppressed ? 'allow' : finding.decision;
}

export function exitCodeForFindings(findings: PackageFinding[], strict = false): number {
  return findings.some((finding) => !finding.suppressed && shouldFail(finding.decision, strict))
    ? 1
    : 0;
}
