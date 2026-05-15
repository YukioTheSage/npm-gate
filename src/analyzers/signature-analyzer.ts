import type { PackageManifest, ProvenanceStatus, RiskSignal } from '../core/types.js';

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
