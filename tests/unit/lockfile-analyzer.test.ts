import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, test } from 'vitest';
import {
  scanPackageLock,
  scanPnpmLock,
  scanYarnLock
} from '../../src/analyzers/lockfile-analyzer.js';

describe('lockfile analyzer', () => {
  test('parses pnpm package keys including scoped, slash-prefixed, quoted, and peer-suffixed keys', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-pnpm-'));
    await writeFile(
      join(cwd, 'pnpm-lock.yaml'),
      [
        "lockfileVersion: '9.0'",
        'packages:',
        '  foo@1.0.0:',
        '    resolution: {integrity: sha512-fixture}',
        '  /bar@2.0.0:',
        '    resolution: {integrity: sha512-fixture}',
        '  "@scope/pkg@3.0.0":',
        '    resolution: {integrity: sha512-fixture}',
        '  baz@4.0.0(peer@2.0.0):',
        '    resolution: {integrity: sha512-fixture}'
      ].join('\n')
    );

    const candidates = await scanPnpmLock(cwd);

    expect(candidates.map(({ name, version }) => ({ name, version }))).toEqual([
      { name: 'foo', version: '1.0.0' },
      { name: 'bar', version: '2.0.0' },
      { name: '@scope/pkg', version: '3.0.0' },
      { name: 'baz', version: '4.0.0' }
    ]);
  });

  test('extracts package names from nested and scoped package-lock package paths', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-package-lock-'));
    await writeFile(
      join(cwd, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/foo': { version: '1.0.0' },
          'node_modules/foo/node_modules/bar': { version: '2.0.0' },
          'node_modules/@scope/pkg': { version: '3.0.0' }
        }
      })
    );

    const candidates = await scanPackageLock(cwd);

    expect(candidates.map(({ name, version }) => ({ name, version }))).toEqual([
      { name: 'foo', version: '1.0.0' },
      { name: 'bar', version: '2.0.0' },
      { name: '@scope/pkg', version: '3.0.0' }
    ]);
  });

  test('parses yarn v1 scoped and multi-selector headers', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-yarn-'));
    await writeFile(
      join(cwd, 'yarn.lock'),
      [
        '"@scope/pkg@^1.0.0", "@scope/pkg@~1.0.0":',
        '  version "1.2.3"',
        'foo@^2.0.0, foo@~2.0.0:',
        '  version "2.1.0"'
      ].join('\n')
    );

    const candidates = await scanYarnLock(cwd);

    expect(candidates.map(({ name, version }) => ({ name, version }))).toEqual([
      { name: '@scope/pkg', version: '1.2.3' },
      { name: '@scope/pkg', version: '1.2.3' },
      { name: 'foo', version: '2.1.0' },
      { name: 'foo', version: '2.1.0' }
    ]);
  });
});
