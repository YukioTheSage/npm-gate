import type {
  ExpectedProvenanceRule,
  PackageManifest,
  ProvenanceStatus,
  RiskSignal,
  TrustedPublishingRule
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

export function trustedPublishingSignals(input: {
  manifest: PackageManifest;
  packageName: string;
  required: boolean;
  expected?: TrustedPublishingRule;
}): RiskSignal[] {
  const provenance = provenanceObject(input.manifest);
  const hasTrustedSignal = Boolean(
    provenance.repository || provenance.workflow || provenance.issuer
  );

  if (input.required && !hasTrustedSignal) {
    return [
      {
        id: 'missing-trusted-publishing',
        score: 55,
        severity: 'high',
        riskCategory: 'provenance_risk',
        message: `Trusted publishing evidence is missing for ${input.packageName}`,
        evidence: [
          { type: 'trusted-publishing', message: 'No trusted publishing metadata found' }
        ],
        remediation: ['Use npm trusted publishing or document an approved release exception.'],
        canOverride: true
      }
    ];
  }

  if (!input.expected) return [];
  const mismatches: Array<{ field: string; expected: string; actual: unknown }> = [];
  for (const field of ['repository', 'workflow', 'issuer'] as const) {
    const expected = input.expected[field];
    if (!expected) continue;
    if (provenance[field] !== expected) {
      mismatches.push({ field, expected, actual: provenance[field] });
    }
  }

  if (mismatches.length === 0) return [];

  return [
    {
      id: 'trusted-publishing-source-mismatch',
      score: 65,
      severity: 'high',
      riskCategory: 'provenance_risk',
      message: `Trusted publishing metadata did not match policy for ${input.packageName}`,
      evidence: [
        {
          type: 'trusted-publishing',
          message: 'Trusted publishing mismatch',
          value: mismatches
        }
      ],
      remediation: ['Verify the release workflow and trusted publisher configuration.'],
      canOverride: true
    }
  ];
}
