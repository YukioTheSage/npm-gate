import { describe, expect, test } from 'vitest';
import { createSarifReport } from '../../src/reporting/sarif-reporter.js';

describe('SARIF reporter', () => {
  test('preserves existing properties and includes enriched security fields', () => {
    const sarif = createSarifReport({
      startedAt: '2026-05-15T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'ci',
      policyMode: 'strict',
      configSource: 'default',
      summary: { allow: 0, warn: 0, block: 1, suppressed: 0 },
      findings: [
        {
          id: 'lifecycle-script:fixture@1.0.1',
          package: 'fixture',
          version: '1.0.1',
          decision: 'block',
          severity: 'high',
          score: 80,
          reasons: ['Lifecycle script detected: postinstall'],
          evidence: [],
          remediation: ['Remove the lifecycle script'],
          canOverride: false,
          riskCategory: 'lifecycle_script_risk',
          matchedSignals: ['lifecycle-script', 'new-lifecycle-script'],
          evidenceSummary: 'postinstall was added in a patch release',
          recommendedFix: 'Remove or narrowly allowlist the script',
          policyMode: 'strict',
          dependencyPath: ['root@1.0.0', 'fixture@1.0.1'],
          allowlist: { used: false, failures: ['script command hash mismatch'] },
          killChain: 'Blocked install-time code execution'
        }
      ]
    }) as any;

    const result = sarif.runs[0].results[0];
    expect(result.level).toBe('error');
    expect(result.properties).toMatchObject({
      package: 'fixture',
      version: '1.0.1',
      score: 80,
      decision: 'block',
      severity: 'high',
      riskCategory: 'lifecycle_script_risk',
      policyMode: 'strict',
      matchedSignals: ['lifecycle-script', 'new-lifecycle-script'],
      evidenceSummary: 'postinstall was added in a patch release',
      recommendedFix: 'Remove or narrowly allowlist the script',
      dependencyPath: ['root@1.0.0', 'fixture@1.0.1'],
      allowlist: { used: false, failures: ['script command hash mismatch'] },
      killChain: 'Blocked install-time code execution',
      canOverride: false,
      suppressed: false
    });
  });

  test('maps manual review findings to SARIF warnings', () => {
    const sarif = createSarifReport({
      startedAt: '2026-05-15T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      policyMode: 'balanced',
      configSource: 'default',
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 },
      findings: [
        {
          id: 'dependency-delta:fixture@1.0.1',
          package: 'fixture',
          version: '1.0.1',
          decision: 'manual_review',
          severity: 'medium',
          score: 35,
          reasons: ['Patch release added a dependency'],
          evidence: [],
          remediation: ['Review dependency delta'],
          canOverride: true
        }
      ]
    }) as any;

    expect(sarif.runs[0].results[0].level).toBe('warning');
  });
});
