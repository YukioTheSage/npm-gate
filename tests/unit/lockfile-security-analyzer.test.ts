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

  test('blocks pnpm resolved hosts outside approved registries', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-pnpm-host-'));
    await writeFile(
      join(cwd, 'pnpm-lock.yaml'),
      [
        'lockfileVersion: "9.0"',
        'packages:',
        '  left-pad@1.3.0:',
        '    resolution:',
        '      tarball: https://evil.example/left-pad/-/left-pad-1.3.0.tgz',
        '      integrity: sha512-current'
      ].join('\n')
    );

    const signals = await analyzeLockfileSecurity(cwd, {
      approvedRegistryHosts: ['registry.npmjs.org']
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'unapproved-resolved-host',
        evidence: [
          expect.objectContaining({
            value: expect.objectContaining({
              file: 'pnpm-lock.yaml',
              package: 'left-pad',
              host: 'evil.example'
            })
          })
        ]
      })
    ]);
  });

  test('blocks yarn resolved hosts outside approved registries', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-yarn-host-'));
    await writeFile(
      join(cwd, 'yarn.lock'),
      [
        '"left-pad@^1.3.0":',
        '  version "1.3.0"',
        '  resolved "https://evil.example/left-pad/-/left-pad-1.3.0.tgz#abc"',
        '  integrity sha512-current'
      ].join('\n')
    );

    const signals = await analyzeLockfileSecurity(cwd, {
      approvedRegistryHosts: ['registry.npmjs.org']
    });

    expect(signals[0]).toEqual(
      expect.objectContaining({
        id: 'unapproved-resolved-host',
        evidence: [
          expect.objectContaining({
            value: expect.objectContaining({
              file: 'yarn.lock',
              package: 'left-pad',
              host: 'evil.example'
            })
          })
        ]
      })
    );
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

  test('blocks pnpm integrity changes when package name and version did not change', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-pnpm-integrity-'));
    const current = join(cwd, 'pnpm-lock.yaml');
    const previous = join(cwd, 'pnpm-lock.previous.yaml');
    await writeFile(
      previous,
      [
        'lockfileVersion: "9.0"',
        'packages:',
        '  left-pad@1.3.0:',
        '    resolution:',
        '      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
        '      integrity: sha512-previous'
      ].join('\n')
    );
    await writeFile(
      current,
      [
        'lockfileVersion: "9.0"',
        'packages:',
        '  left-pad@1.3.0:',
        '    resolution:',
        '      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
        '      integrity: sha512-current'
      ].join('\n')
    );

    const signals = await analyzeLockfileSecurity(cwd, {
      approvedRegistryHosts: ['registry.npmjs.org'],
      previousPnpmLockPath: previous
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'lockfile-integrity-changed',
        evidence: [
          expect.objectContaining({
            value: expect.objectContaining({
              file: 'pnpm-lock.yaml',
              package: 'left-pad',
              previousIntegrity: 'sha512-previous',
              currentIntegrity: 'sha512-current'
            })
          })
        ]
      })
    ]);
  });

  test('blocks yarn integrity changes when package name and version did not change', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-yarn-integrity-'));
    const current = join(cwd, 'yarn.lock');
    const previous = join(cwd, 'yarn.previous.lock');
    await writeFile(
      previous,
      [
        '"left-pad@^1.3.0":',
        '  version "1.3.0"',
        '  resolved "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz#abc"',
        '  integrity sha512-previous'
      ].join('\n')
    );
    await writeFile(
      current,
      [
        '"left-pad@^1.3.0":',
        '  version "1.3.0"',
        '  resolved "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz#abc"',
        '  integrity sha512-current'
      ].join('\n')
    );

    const signals = await analyzeLockfileSecurity(cwd, {
      approvedRegistryHosts: ['registry.npmjs.org'],
      previousYarnLockPath: previous
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'lockfile-integrity-changed',
        evidence: [
          expect.objectContaining({
            value: expect.objectContaining({
              file: 'yarn.lock',
              package: 'left-pad',
              previousIntegrity: 'sha512-previous',
              currentIntegrity: 'sha512-current'
            })
          })
        ]
      })
    ]);
  });
});
