import semver from 'semver';
import type { EmergencyDenylistEntry, PackageCandidate, RiskSignal } from '../core/types.js';

export interface EmergencyChecklist {
  credentialRotation: string[];
  ciCleanup: string[];
}

function versionMatches(version: string | undefined, ranges: string[]): boolean {
  if (!version) return false;
  return ranges.some((range) => {
    if (range === version) return true;
    try {
      return semver.satisfies(version, range, { includePrerelease: true });
    } catch {
      return false;
    }
  });
}

export function emergencyDenylistSignals(
  candidate: PackageCandidate,
  denylist: EmergencyDenylistEntry[],
  dependencyPath?: string[]
): RiskSignal[] {
  return denylist
    .filter((entry) => entry.package === candidate.name && versionMatches(candidate.version, entry.versions))
    .map((entry) => ({
      id: 'emergency-denylist-match',
      score: 100,
      severity: 'critical' as const,
      riskCategory: 'emergency_denylist_risk' as const,
      matchedSignals: ['known bad package version'],
      dependencyPath,
      message: `Emergency denylist matched ${candidate.name}@${candidate.version ?? 'unknown'}`,
      evidence: [
        {
          type: 'emergency-denylist',
          message: entry.reason,
          value: {
            package: entry.package,
            versions: entry.versions,
            dependencyPath
          }
        }
      ],
      remediation: [
        'Remove or pin away from the affected version.',
        ...createEmergencyChecklist().credentialRotation,
        ...createEmergencyChecklist().ciCleanup
      ],
      canOverride: false
    }));
}

export function createEmergencyChecklist(): EmergencyChecklist {
  return {
    credentialRotation: [
      'Rotate npm tokens',
      'Rotate GitHub tokens',
      'Rotate cloud credentials reachable from install or CI jobs',
      'Review SSH keys and deploy keys'
    ],
    ciCleanup: [
      'Clear package-manager caches',
      'Review GitHub Actions workflow changes',
      'Inspect release workflow logs for unauthorized publishes',
      'Check for malicious workflow additions or modified release pipelines'
    ]
  };
}
