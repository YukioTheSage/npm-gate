import { describe, expect, test } from 'vitest';
import { resolveDependencyClosure } from '../../src/analyzers/dependency-closure-analyzer.js';
import type { PackageMetadata, RegistryClient } from '../../src/core/types.js';

function registry(fixtures: Record<string, PackageMetadata>): RegistryClient {
  return {
    async getPackageMetadata(name: string) {
      const metadata = fixtures[name];
      if (!metadata) throw new Error(`missing fixture for ${name}`);
      return metadata;
    },
    async resolveVersion(name: string, range = '*') {
      const metadata = fixtures[name];
      if (!metadata) throw new Error(`missing fixture for ${name}`);
      if (metadata.versions[range]) return range;
      const latest = metadata['dist-tags']?.latest;
      if (!latest) throw new Error(`missing latest for ${name}`);
      return latest;
    }
  };
}

describe('dependency closure analyzer', () => {
  test('dedupes transitive dependencies and records dependency paths', async () => {
    const closure = await resolveDependencyClosure(
      {
        manifest: {
          name: 'root',
          version: '1.0.0',
          dependencies: { alpha: '^1.0.0', beta: '^1.0.0' }
        },
        registry: registry({
          alpha: {
            name: 'alpha',
            versions: {
              '1.0.0': {
                name: 'alpha',
                version: '1.0.0',
                dependencies: { shared: '^1.0.0' }
              }
            },
            'dist-tags': { latest: '1.0.0' }
          },
          beta: {
            name: 'beta',
            versions: {
              '1.0.0': {
                name: 'beta',
                version: '1.0.0',
                optionalDependencies: { shared: '^1.0.0' }
              }
            },
            'dist-tags': { latest: '1.0.0' }
          },
          shared: {
            name: 'shared',
            versions: {
              '1.0.0': {
                name: 'shared',
                version: '1.0.0'
              }
            },
            'dist-tags': { latest: '1.0.0' }
          }
        }),
        maxPackages: 10
      }
    );

    expect(closure.map(({ name, version, dependencyPath }) => ({ name, version, dependencyPath })))
      .toEqual([
        { name: 'alpha', version: '1.0.0', dependencyPath: ['root@1.0.0', 'alpha@1.0.0'] },
        { name: 'beta', version: '1.0.0', dependencyPath: ['root@1.0.0', 'beta@1.0.0'] },
        {
          name: 'shared',
          version: '1.0.0',
          dependencyPath: ['root@1.0.0', 'alpha@1.0.0', 'shared@1.0.0']
        }
      ]);
  });

  test('fails closed when the dependency closure exceeds the configured package cap', async () => {
    await expect(
      resolveDependencyClosure({
        manifest: { name: 'root', version: '1.0.0', dependencies: { alpha: '1.0.0' } },
        registry: registry({
          alpha: {
            name: 'alpha',
            versions: { '1.0.0': { name: 'alpha', version: '1.0.0' } },
            'dist-tags': { latest: '1.0.0' }
          }
        }),
        maxPackages: 0
      })
    ).rejects.toThrow(/exceeds configured maximum/);
  });
});
