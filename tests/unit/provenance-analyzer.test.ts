import { describe, expect, test } from 'vitest';
import {
  expectedProvenanceSignals,
  trustedPublishingSignals
} from '../../src/analyzers/provenance-analyzer.js';

describe('provenance analyzer', () => {
  test('treats expected provenance as publish-path evidence and flags mismatches', () => {
    const signals = expectedProvenanceSignals(
      {
        name: 'fixture',
        version: '1.0.0',
        dist: {
          provenance: {
            repository: 'https://github.com/attacker/fixture',
            workflow: '.github/workflows/release.yml',
            ref: 'refs/heads/main'
          }
        }
      },
      {
        package: 'fixture',
        repository: 'https://github.com/example/fixture',
        workflow: '.github/workflows/release.yml',
        ref: 'refs/heads/main'
      }
    );

    expect(signals.map((signal) => signal.id)).toContain('unexpected-provenance-source');
    expect(signals[0]?.remediation?.join(' ')).toContain(
      'Provenance proves publish path, not package safety.'
    );
  });

  test('does not emit a mismatch when expected provenance matches', () => {
    const signals = expectedProvenanceSignals(
      {
        name: 'fixture',
        version: '1.0.0',
        dist: {
          provenance: {
            repository: 'https://github.com/example/fixture',
            workflow: '.github/workflows/release.yml'
          }
        }
      },
      {
        package: 'fixture',
        repository: 'https://github.com/example/fixture',
        workflow: '.github/workflows/release.yml'
      }
    );

    expect(signals).toEqual([]);
  });

  test('flags missing trusted publishing for required high impact package', () => {
    const signals = trustedPublishingSignals({
      manifest: { name: '@company/core', version: '1.0.0', dist: {} },
      packageName: '@company/core',
      required: true
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'missing-trusted-publishing',
        severity: 'high'
      })
    ]);
  });

  test('flags trusted publishing metadata mismatches', () => {
    const signals = trustedPublishingSignals({
      manifest: {
        name: '@company/core',
        version: '1.0.0',
        dist: {
          provenance: {
            repository: 'company/core',
            workflow: '.github/workflows/release.yml'
          }
        }
      },
      packageName: '@company/core',
      required: true,
      expected: {
        package: '@company/core',
        repository: 'company/core',
        workflow: '.github/workflows/publish.yml'
      }
    });

    expect(signals.map((signal) => signal.id)).toContain(
      'trusted-publishing-source-mismatch'
    );
  });
});
