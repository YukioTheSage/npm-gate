import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { resolvePackageManager } from '../../src/wrappers/package-manager-runner.js';
import { resolveCommandForSpawn, runCommand } from '../../src/utils/exec.js';

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

  test('resolves Windows package-manager shims to node-backed commands without a shell', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-safe-spawn-'));
    const cliPath = join(cwd, 'node_modules', 'npm', 'bin', 'npm-cli.js');
    await mkdir(dirname(cliPath), { recursive: true });
    await writeFile(
      cliPath,
      'process.stdout.write(JSON.stringify(process.argv.slice(2)))\n',
      'utf8'
    );
    await writeFile(join(cwd, 'npm.cmd'), '@ECHO off\r\nnode "%~dp0\\node_modules\\npm\\bin\\npm-cli.js" %*\r\n');

    const resolved = await resolveCommandForSpawn(
      'npm',
      ['install', 'safe&echo injected'],
      {
        platform: 'win32',
        execPath: process.execPath,
        env: { PATH: cwd }
      }
    );

    expect(resolved).toEqual({
      command: process.execPath,
      args: [cliPath, 'install', 'safe&echo injected']
    });

    const result = await runCommand(resolved.command, resolved.args, cwd);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(['install', 'safe&echo injected']);
    expect(result.stdout).not.toContain('\ninjected');
  });
});
