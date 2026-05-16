import { describe, expect, test } from 'vitest';
import { signatureVerificationSignals } from '../../src/analyzers/signature-analyzer.js';

describe('signature analyzer', () => {
  test('blocks required unavailable cryptographic verification', () => {
    const signals = signatureVerificationSignals({
      packageName: 'left-pad',
      version: '1.3.0',
      required: true,
      result: { status: 'unavailable', message: 'npm audit signatures not found' }
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'signature-verification-unavailable',
        severity: 'high',
        canOverride: false
      })
    ]);
  });

  test('emits no risk for verified signatures and attestations', () => {
    const signals = signatureVerificationSignals({
      packageName: 'left-pad',
      version: '1.3.0',
      required: true,
      result: { status: 'verified', signaturesVerified: true, provenanceVerified: true }
    });

    expect(signals).toEqual([]);
  });

  test('emits reviewable risk for optional invalid verification', () => {
    const signals = signatureVerificationSignals({
      packageName: 'left-pad',
      version: '1.3.0',
      required: false,
      result: { status: 'invalid', message: 'malformed verification output' }
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'signature-verification-failed',
        severity: 'medium',
        canOverride: true
      })
    ]);
  });
});
