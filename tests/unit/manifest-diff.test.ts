import { describe, expect, test } from 'vitest';
import { dependencyDiffSignals } from '../../src/analyzers/dependency-diff-analyzer.js';
import { diffManifests } from '../../src/analyzers/manifest-analyzer.js';

describe('manifest diffing', () => {
  test('flags new lifecycle hooks and newly added dependencies', () => {
    const diff = diffManifests(
      {
        name: 'fixture',
        version: '1.0.0',
        dependencies: { existing: '1.0.0' }
      },
      {
        name: 'fixture',
        version: '1.0.1',
        scripts: { preinstall: 'node fixture.js' },
        dependencies: { existing: '1.0.0', added: '^1.0.0' }
      }
    );

    expect(diff.newLifecycleScripts).toEqual([{ name: 'preinstall', command: 'node fixture.js' }]);
    expect(diff.newDependencies).toEqual([
      { section: 'dependencies', name: 'added', spec: '^1.0.0' }
    ]);
  });

  test('flags registry dependency switching to a git dependency', () => {
    const diff = diffManifests(
      { name: 'fixture', version: '1.0.0', optionalDependencies: { dep: '^1.0.0' } },
      { name: 'fixture', version: '1.0.1', optionalDependencies: { dep: 'github:owner/repo#main' } }
    );

    expect(diff.gitDependencySwitches).toEqual([
      {
        section: 'optionalDependencies',
        name: 'dep',
        previous: '^1.0.0',
        current: 'github:owner/repo#main'
      }
    ]);
  });

  test('flags patch and minor releases that add dependencies for manual review', () => {
    const patchSignals = dependencyDiffSignals(
      { name: 'fixture', version: '1.0.0', dependencies: { leftpad: '1.0.0' } },
      {
        name: 'fixture',
        version: '1.0.1',
        dependencies: { leftpad: '1.0.0', hidden: '1.0.0' }
      }
    );

    expect(patchSignals.map((signal) => signal.id)).toContain('new-dependency-in-patch-release');
    expect(
      patchSignals.find((signal) => signal.id === 'new-dependency-in-patch-release')?.manualReview
    ).toBe(true);

    const majorSignals = dependencyDiffSignals(
      { name: 'fixture', version: '1.0.0', dependencies: { leftpad: '1.0.0' } },
      {
        name: 'fixture',
        version: '2.0.0',
        dependencies: { leftpad: '1.0.0', expected: '1.0.0' }
      }
    );

    expect(majorSignals.map((signal) => signal.id)).not.toContain(
      'new-dependency-in-patch-release'
    );
  });
});
