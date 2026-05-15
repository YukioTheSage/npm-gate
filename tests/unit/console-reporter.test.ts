import { describe, expect, test } from 'vitest';
import { renderConsoleReport } from '../../src/reporting/console-reporter.js';

describe('console reporter', () => {
  test('prints policy mode, manual review count, and enriched finding context', () => {
    const output = renderConsoleReport({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
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
          score: 85,
          reasons: ['Lifecycle script detected: postinstall'],
          evidence: [],
          remediation: ['Remove the lifecycle script or add a narrow script hash allowlist entry'],
          canOverride: false,
          riskCategory: 'lifecycle_script_risk',
          matchedSignals: ['lifecycle-script', 'new-lifecycle-script'],
          evidenceSummary: 'postinstall changed in patch release',
          recommendedFix: 'Review the package artifact before installation',
          dependencyPath: ['root@1.0.0', 'fixture@1.0.1'],
          killChain:
            'package@x.y.z added a new postinstall script, creating install-time code execution risk.'
        },
        {
          id: 'dependency-delta:review@1.0.1',
          package: 'review',
          version: '1.0.1',
          decision: 'manual_review',
          severity: 'medium',
          score: 45,
          reasons: ['Patch release added a new dependency'],
          evidence: [],
          remediation: ['Review dependency delta'],
          canOverride: true
        }
      ]
    });

    expect(output).toContain('npm-gate warn report (strict policy)');
    expect(output).toContain('1 manual review');
    expect(output).toContain('Risk category: lifecycle_script_risk');
    expect(output).toContain('Matched signals: lifecycle-script, new-lifecycle-script');
    expect(output).toContain('Dependency path: root@1.0.0 > fixture@1.0.1');
    expect(output).toContain('Kill chain: package@x.y.z added a new postinstall script');
  });
});
