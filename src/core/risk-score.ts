import type { RiskSignal, Severity } from './types.js';

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function severityFromScore(score: number): Severity {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function maxSeverity(severities: Severity[]): Severity {
  return severities.reduce<Severity>(
    (highest, current) => (severityRank[current] > severityRank[highest] ? current : highest),
    'info'
  );
}

export function scoreSignals(signals: RiskSignal[]): { score: number; severity: Severity } {
  const score = Math.min(
    100,
    signals.reduce((total, signal) => total + Math.max(0, signal.score), 0)
  );
  return {
    score,
    severity: maxSeverity([severityFromScore(score), ...signals.map((signal) => signal.severity)])
  };
}
