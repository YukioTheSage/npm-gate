import type {
  ExpectedProvenanceRule,
  PackageManifest,
  ProvenanceStatus,
  RiskSignal
} from '../core/types.js';

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
    riskCategory: 'provenance_risk',
    message: `Provenance is ${status} for high-impact package ${packageName}`,
    evidence: [{ type: 'provenance', message: 'Best-effort provenance status', value: status }],
    remediation: [
      'Require a provenance-producing release workflow or security approval.',
      'Provenance proves publish path, not package safety.'
    ],
    canOverride: false
  };
}

function provenanceObject(manifest: PackageManifest | undefined): Record<string, unknown> {
  const value = manifest?.dist?.provenance;
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

export function expectedProvenanceSignals(
  manifest: PackageManifest | undefined,
  rule: ExpectedProvenanceRule
): RiskSignal[] {
  const provenance = provenanceObject(manifest);
  const mismatches: Array<{ field: string; expected: string; actual: unknown }> = [];

  for (const field of ['repository', 'workflow', 'ref', 'commitSubject'] as const) {
    const expected = rule[field];
    if (!expected) continue;
    if (provenance[field] !== expected) {
      mismatches.push({ field, expected, actual: provenance[field] });
    }
  }

  if (mismatches.length === 0) return [];

  return [
    {
      id: 'unexpected-provenance-source',
      score: 70,
      severity: 'high',
      riskCategory: 'provenance_risk',
      matchedSignals: mismatches.map((mismatch) => `unexpected ${mismatch.field}`),
      message: `Provenance source does not match policy for ${rule.package}`,
      evidence: [
        {
          type: 'provenance',
          message: 'Expected provenance did not match package metadata',
          value: { package: rule.package, mismatches }
        }
      ],
      remediation: [
        'Block this release until the publish path is reviewed.',
        'Provenance proves publish path, not package safety.'
      ],
      canOverride: false
    }
  ];
}
