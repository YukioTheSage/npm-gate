import type { Severity } from '../core/types.js';

export const severityOrder: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function highestSeverity(values: Severity[]): Severity {
  return values.reduce<Severity>(
    (highest, current) => (severityOrder[current] > severityOrder[highest] ? current : highest),
    'info'
  );
}
