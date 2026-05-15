import { describe, expect, test } from 'vitest';
import { exitCodeForFindings, strictExitForReport } from '../../src/core/decision.js';
import type { PackageFinding, ScanReport } from '../../src/core/types.js';

const manualReviewFinding: PackageFinding = {
  id: 'review:fixture@1.0.0',
  package: 'fixture',
  version: '1.0.0',
  decision: 'manual_review',
  severity: 'medium',
  score: 45,
  reasons: ['Manual review required'],
  evidence: [],
  remediation: [],
  canOverride: true
};

function report(policyMode: ScanReport['policyMode']): Pick<ScanReport, 'policyMode'> {
  return { policyMode };
}

describe('decision helpers', () => {
  test('manual review findings fail only under strict exit handling', () => {
    expect(exitCodeForFindings([manualReviewFinding], false)).toBe(0);
    expect(exitCodeForFindings([manualReviewFinding], true)).toBe(1);
  });

  test('strict exit handling follows strict and emergency policy modes', () => {
    expect(strictExitForReport(report('balanced'), false)).toBe(false);
    expect(strictExitForReport(report('strict'), false)).toBe(true);
    expect(strictExitForReport(report('emergency'), false)).toBe(true);
    expect(strictExitForReport(report(undefined), true)).toBe(true);
  });
});
