import type { RiskSignal } from '../core/types.js';
import { hoursBetween } from '../utils/time.js';

export function releaseAgeSignal(
  publishedAt: string | undefined,
  minimumReleaseAgeHours: number,
  now = new Date()
): RiskSignal | undefined {
  if (!publishedAt) return undefined;

  const ageHours = hoursBetween(new Date(publishedAt), now);
  if (ageHours >= minimumReleaseAgeHours) return undefined;

  return {
    id: 'new-release',
    score: 30,
    severity: 'medium',
    message: `Release is ${Math.floor(ageHours)}h old, below minimum policy age of ${minimumReleaseAgeHours}h`,
    evidence: [{ type: 'registry-time', message: 'Package publish time', value: publishedAt }],
    remediation: ['Wait for the release-age cooldown or pin a previous known-good version.'],
    canOverride: true
  };
}
