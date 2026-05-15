import { describe, expect, test } from 'vitest';
import { artifactDiffSignals } from '../../src/analyzers/artifact-diff-analyzer.js';

describe('artifact diff analyzer', () => {
  test('flags binary additions, source metadata changes, package size and file-count spikes, and tarball/source mismatch', () => {
    const signals = artifactDiffSignals({
      previousManifest: {
        name: 'fixture',
        version: '1.0.0',
        repository: { url: 'https://github.com/example/fixture' }
      },
      currentManifest: {
        name: 'fixture',
        version: '1.0.1',
        repository: { url: 'https://github.com/attacker/fixture' },
        dist: { tarball: 'https://registry.npmjs.org/fixture/-/fixture-1.0.1.tgz' }
      },
      previousEntries: [{ path: 'package/index.js', size: 100 }],
      currentEntries: [
        { path: 'package/index.js', size: 100 },
        { path: 'package/native.node', size: 1000 },
        ...Array.from({ length: 22 }, (_, index) => ({
          path: `package/generated/file-${index}.js`,
          size: 100
        }))
      ],
      previousSize: 1_000,
      currentSize: 151_000,
      sourceTagFound: false
    });

    expect(signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'new-binary-file',
        'source-repository-changed',
        'suspicious-package-size-increase',
        'suspicious-package-file-count-increase',
        'tarball-source-mismatch'
      ])
    );
    expect(signals.every((signal) => signal.riskCategory === 'artifact_diff_risk')).toBe(true);
  });

  test('does not flag large major-version changes solely because they are large', () => {
    const signals = artifactDiffSignals({
      previousManifest: { name: 'fixture', version: '1.0.0' },
      currentManifest: { name: 'fixture', version: '2.0.0' },
      previousSize: 1_000,
      currentSize: 90_000
    });

    expect(signals.map((signal) => signal.id)).not.toContain('suspicious-package-size-increase');
  });
});
