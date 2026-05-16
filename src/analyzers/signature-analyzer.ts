import type { PackageManifest, ProvenanceStatus, RiskSignal } from '../core/types.js';
import type { SignatureVerificationResult } from '../verification/signature-verifier.js';

export function getSignatureStatus(manifest: PackageManifest | undefined): ProvenanceStatus {
  if (!manifest) return 'unknown';
  if (Array.isArray(manifest.dist?.signatures) && manifest.dist.signatures.length > 0)
    return 'present-unverified';
  if (manifest.dist && 'signatures' in manifest.dist) return 'missing';
  return 'unavailable';
}

export function signatureSignal(
  manifest: PackageManifest | undefined,
  warnWhenAvailable: boolean,
  requireSignature = false
): RiskSignal | undefined {
  const status = getSignatureStatus(manifest);
  if (
    (!requireSignature && !warnWhenAvailable) ||
    status === 'present-unverified' ||
    status === 'unavailable' ||
    status === 'unknown'
  ) {
    return undefined;
  }

  return {
    id: 'missing-registry-signature',
    score: requireSignature ? 70 : 15,
    severity: requireSignature ? 'high' : 'low',
    message: `Registry signature data is ${status}`,
    evidence: [
      { type: 'registry-signature', message: 'Best-effort signature status', value: status }
    ],
    remediation: ['Prefer signed releases when registry signature data is available.'],
    canOverride: !requireSignature
  };
}

export function signatureVerificationSignals(input: {
  packageName: string;
  version: string;
  required: boolean;
  result: SignatureVerificationResult;
}): RiskSignal[] {
  if (input.result.status === 'verified') return [];
  return [
    {
      id:
        input.result.status === 'unavailable'
          ? 'signature-verification-unavailable'
          : 'signature-verification-failed',
      score: input.required ? 70 : 35,
      severity: input.required ? 'high' : 'medium',
      riskCategory: 'provenance_risk',
      message: `Cryptographic signature verification ${input.result.status} for ${input.packageName}@${input.version}`,
      evidence: [
        {
          type: 'signature-verification',
          message: input.result.message ?? input.result.status,
          value: input.result
        }
      ],
      remediation: ['Verify npm registry signatures and provenance attestations before release.'],
      canOverride: !input.required
    }
  ];
}
