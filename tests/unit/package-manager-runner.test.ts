import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { resolvePackageManager } from '../../src/wrappers/package-manager-runner.js';

describe('package manager runner', () => {
  test('prefers explicit package manager, then environment, then pnpm lockfile, then npm', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-package-manager-'));

    await expect(
      resolvePackageManager({ cwd, env: {}, requested: 'pnpm' })
    ).resolves.toBe('pnpm');
    await expect(
      resolvePackageManager({ cwd, env: { NPM_GATE_PACKAGE_MANAGER: 'pnpm' } })
    ).resolves.toBe('pnpm');
    await expect(resolvePackageManager({ cwd, env: {} })).resolves.toBe('npm');

    await writeFile(join(cwd, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');

    await expect(resolvePackageManager({ cwd, env: {} })).resolves.toBe('pnpm');
  });

  test('rejects unsupported package managers', async () => {
    await expect(
      resolvePackageManager({
        cwd: process.cwd(),
        env: { NPM_GATE_PACKAGE_MANAGER: 'yarn' }
      })
    ).rejects.toThrow(/Unsupported package manager/);
  });
});
