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
});
