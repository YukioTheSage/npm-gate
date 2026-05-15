import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { analyzeLockfileSecurity } from '../../src/analyzers/lockfile-security-analyzer.js';

describe('lockfile security analyzer', () => {
  test('blocks package-lock resolved hosts outside approved registries', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-lock-host-'));
    await writeFile(
      join(cwd, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/left-pad': {
            version: '1.3.0',
            resolved: 'https://evil.example/left-pad/-/left-pad-1.3.0.tgz',
            integrity: 'sha512-current'
          }
        }
      })
    );

    const signals = await analyzeLockfileSecurity(cwd, {
      approvedRegistryHosts: ['registry.npmjs.org']
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'unapproved-resolved-host',
        message: 'Lockfile resolves package tarball from an unapproved host'
      })
    ]);
  });

  test('blocks integrity changes when package name and version did not change', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-lock-integrity-'));
    const current = join(cwd, 'package-lock.json');
    const previous = join(cwd, 'package-lock.previous.json');
    await writeFile(
      previous,
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          'node_modules/left-pad': {
            version: '1.3.0',
            resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
            integrity: 'sha512-previous'
          }
        }
      })
    );
    await writeFile(
      current,
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          'node_modules/left-pad': {
            version: '1.3.0',
            resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
            integrity: 'sha512-current'
          }
        }
      })
    );

    const signals = await analyzeLockfileSecurity(cwd, {
      approvedRegistryHosts: ['registry.npmjs.org'],
      previousPackageLockPath: previous
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'lockfile-integrity-changed',
        message: 'Lockfile integrity changed without a package version change'
      })
    ]);
  });
});
