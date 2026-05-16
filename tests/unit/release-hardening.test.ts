import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { verifyPublishedDependencyTree } from '../../scripts/verify-published-dependency-tree.mjs';

describe('published dependency tree verification', () => {
  test('rejects package metadata without shrinkwrap when runtime dependencies exist', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-release-deps-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { commander: '^14.0.3' } })
    );

    await expect(verifyPublishedDependencyTree(cwd)).rejects.toThrow(/npm-shrinkwrap.json/);
  });

  test('accepts exact shrinkwrap for runtime dependencies', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-release-deps-ok-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { commander: '^14.0.3' } })
    );
    await writeFile(
      join(cwd, 'npm-shrinkwrap.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { commander: '^14.0.3' } },
          'node_modules/commander': { version: '14.0.3', integrity: 'sha512-fixture' }
        }
      })
    );

    await expect(verifyPublishedDependencyTree(cwd)).resolves.toBeUndefined();
  });
});
