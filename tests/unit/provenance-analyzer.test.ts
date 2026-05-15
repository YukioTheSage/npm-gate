import { describe, expect, test } from 'vitest';
import { expectedProvenanceSignals } from '../../src/analyzers/provenance-analyzer.js';

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
});
