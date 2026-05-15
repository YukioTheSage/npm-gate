import { describe, expect, test } from 'vitest';
import { scoreSignals } from '../../src/core/risk-score.js';

describe('risk scoring', () => {
  test('adds signal weights deterministically and caps the score at 100', () => {
    const score = scoreSignals([
      { id: 'new-release', score: 30, severity: 'medium', message: 'new release' },
      { id: 'lifecycle-script', score: 45, severity: 'high', message: 'postinstall' },
      { id: 'known-malicious-advisory', score: 80, severity: 'critical', message: 'malicious' }
    ]);

    expect(score.score).toBe(100);
    expect(score.severity).toBe('critical');
  });
});
