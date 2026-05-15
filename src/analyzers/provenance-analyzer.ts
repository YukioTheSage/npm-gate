import type { PackageManifest, ProvenanceStatus, RiskSignal } from '../core/types.js';

export function getProvenanceStatus(manifest: PackageManifest | undefined): ProvenanceStatus {
  if (!manifest) return 'unknown';
  if (manifest.dist?.provenance === true) return 'verified';
  if (manifest.dist?.provenance) return 'present-unverified';
  return 'unknown';
}

export function provenanceSignal(
  manifest: PackageManifest | undefined,
  packageName: string,
  requiresProvenance: boolean
): RiskSignal | undefined {
  const status = getProvenanceStatus(manifest);
  if (!requiresProvenance || status === 'verified' || status === 'present-unverified')
    return undefined;

  return {
    id: 'missing-provenance',
    score: 70,
    severity: 'high',
    message: `Provenance is ${status} for high-impact package ${packageName}`,
    evidence: [{ type: 'provenance', message: 'Best-effort provenance status', value: status }],
    remediation: ['Require a provenance-producing release workflow or security approval.'],
    canOverride: false
  };
}
