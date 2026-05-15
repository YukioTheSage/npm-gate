import { describe, expect, test } from 'vitest';
import { createJsonReport } from '../../src/reporting/json-reporter.js';

describe('JSON reporter', () => {
  test('includes summary counts, runtime metadata, and findings', () => {
    const report = createJsonReport({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'ci',
      policyPath: 'npm-gate.config.json',
      configSource: 'file',
      findings: [
        {
          id: 'new-release:fixture@1.0.0',
          package: 'fixture',
          version: '1.0.0',
          decision: 'warn',
          score: 45,
          severity: 'medium',
          reasons: ['New release'],
          evidence: [],
          remediation: ['Wait for release age cooldown'],
          canOverride: true
        }
      ]
    });

    expect(report.summary).toEqual({ allow: 0, warn: 1, block: 0, suppressed: 0 });
    expect(report.mode).toBe('ci');
    expect(report.findings[0]?.package).toBe('fixture');
  });
});
