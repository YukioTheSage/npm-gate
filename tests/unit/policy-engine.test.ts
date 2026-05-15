import { describe, expect, test } from 'vitest';
import { defaultPolicy } from '../../src/config/default-policy.js';
import { decidePackage } from '../../src/policy/policy-engine.js';

describe('policy engine', () => {
  test('allows clean packages below warn threshold', () => {
    const finding = decidePackage({
      candidate: { name: 'clean-package', version: '1.0.0' },
      policy: defaultPolicy,
      mode: 'warn',
      signals: []
    });

    expect(finding.decision).toBe('allow');
  });

  test('blocks high score packages and turns warnings into blocks in strict mode', () => {
    const warn = decidePackage({
      candidate: { name: 'fixture', version: '1.0.0' },
      policy: defaultPolicy,
      mode: 'warn',
      signals: [{ id: 'new-release', score: 45, severity: 'medium', message: 'new release' }]
    });

    expect(warn.decision).toBe('warn');

    const block = decidePackage({
      candidate: { name: 'fixture', version: '1.0.0' },
      policy: defaultPolicy,
      mode: 'warn',
      signals: [
        { id: 'known-malicious-advisory', score: 80, severity: 'critical', message: 'malicious' }
      ]
    });

    expect(block.decision).toBe('block');

    const strict = decidePackage({
      candidate: { name: 'fixture', version: '1.0.0' },
      policy: defaultPolicy,
      mode: 'warn',
      strict: true,
      signals: [{ id: 'new-release', score: 45, severity: 'medium', message: 'new release' }]
    });

    expect(strict.decision).toBe('block');
  });

  test('blocks hard production guardrail signals regardless of aggregate score', () => {
    for (const signalId of [
      'registry-tarball-integrity-mismatch',
      'required-intelligence-unavailable',
      'unapproved-resolved-host',
      'lockfile-integrity-changed',
      'workflow-dangerous-trigger',
      'workflow-untrusted-checkout',
      'workflow-cache-poisoning-risk',
      'workflow-overprivileged-token',
      'provenance-source-mismatch'
    ]) {
      const finding = decidePackage({
        candidate: { name: 'fixture', version: '1.0.0' },
        policy: defaultPolicy,
        mode: 'ci',
        signals: [{ id: signalId, score: 10, severity: 'medium', message: signalId }]
      });

      expect(finding.decision, signalId).toBe('block');
    }
  });

  test('blocks high-risk static malware signals in CI but warns locally', () => {
    for (const signalId of [
      'credential-harvesting-pattern',
      'install-downloader-pattern',
      'child-process-network-exfil'
    ]) {
      const local = decidePackage({
        candidate: { name: 'fixture', version: '1.0.0' },
        policy: defaultPolicy,
        mode: 'warn',
        signals: [{ id: signalId, score: 60, severity: 'high', message: signalId }]
      });
      expect(local.decision, `${signalId} local`).toBe('warn');

      const ci = decidePackage({
        candidate: { name: 'fixture', version: '1.0.0' },
        policy: defaultPolicy,
        mode: 'ci',
        signals: [{ id: signalId, score: 10, severity: 'medium', message: signalId }]
      });
      expect(ci.decision, `${signalId} ci`).toBe('block');
    }
  });

  test('produces manual review decisions and enriched finding fields', () => {
    const finding = decidePackage({
      candidate: { name: 'fixture', version: '1.2.3' },
      policy: { ...defaultPolicy, policyMode: 'balanced' },
      mode: 'warn',
      policyMode: 'balanced',
      signals: [
        {
          id: 'new-dependency-in-patch-release',
          score: 30,
          severity: 'medium',
          message: 'Patch release introduced a new dependency',
          riskCategory: 'dependency_delta_risk',
          matchedSignals: ['patch dependency delta'],
          evidence: [
            {
              type: 'manifest-diff',
              message: 'New dependency added in patch release',
              value: { dependencyPath: ['fixture@1.2.3', 'new-dep@1.0.0'] }
            }
          ],
          remediation: ['Review the new dependency chain before install.'],
          canOverride: true,
          manualReview: true
        }
      ]
    });

    expect(finding.decision).toBe('manual_review');
    expect(finding.riskCategory).toBe('dependency_delta_risk');
    expect(finding.policyMode).toBe('balanced');
    expect(finding.matchedSignals).toEqual(['new-dependency-in-patch-release', 'patch dependency delta']);
    expect(finding.evidenceSummary).toContain('New dependency added in patch release');
    expect(finding.recommendedFix).toBe('Review the new dependency chain before install.');
  });

  test('package allowlists do not suppress lifecycle execution risk', () => {
    const finding = decidePackage({
      candidate: { name: 'fixture', version: '1.0.0' },
      policy: defaultPolicy,
      mode: 'ci',
      policyMode: 'strict',
      allowlisted: true,
      signals: [
        {
          id: 'lifecycle-install-downloader',
          score: 70,
          severity: 'critical',
          message: 'Lifecycle script downloads and executes remote code',
          riskCategory: 'lifecycle_script_risk',
          evidence: [{ type: 'manifest-script', message: 'postinstall script is present' }],
          remediation: ['Remove the downloader lifecycle script.'],
          canOverride: false
        }
      ]
    });

    expect(finding.decision).toBe('block');
    expect(finding.allowlist?.used).toBe(true);
    expect(finding.allowlist?.scope).toBe('package');
  });

  test('strict policy blocks high-confidence frontend runtime mutation signals', () => {
    for (const signalId of [
      'frontend-runtime-wallet-access',
      'frontend-runtime-clipboard-mutation',
      'frontend-runtime-transaction-mutation'
    ]) {
      const balanced = decidePackage({
        candidate: { name: 'frontend-fixture', version: '1.0.1' },
        policy: defaultPolicy,
        mode: 'warn',
        policyMode: 'balanced',
        signals: [{ id: signalId, score: 40, severity: 'medium', message: signalId }]
      });
      expect(balanced.decision, `${signalId} balanced`).toBe('manual_review');

      const strict = decidePackage({
        candidate: { name: 'frontend-fixture', version: '1.0.1' },
        policy: defaultPolicy,
        mode: 'warn',
        policyMode: 'strict',
        signals: [{ id: signalId, score: 40, severity: 'medium', message: signalId }]
      });
      expect(strict.decision, `${signalId} strict`).toBe('block');
    }
  });
});
