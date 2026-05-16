import { EventEmitter } from 'node:events';
import { describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  spawn: vi.fn(),
  resolveCommandForSpawn: vi.fn(),
  redactSecrets: vi.fn((value: string) => value)
}));

vi.mock('node:child_process', () => ({
  spawn: mocks.spawn
}));

vi.mock('../../src/utils/exec.js', () => ({
  resolveCommandForSpawn: mocks.resolveCommandForSpawn,
  redactSecrets: mocks.redactSecrets
}));

const { runPackageManager } = await import('../../src/wrappers/package-manager-runner.js');

describe('package manager runner env override', () => {
  test('passes explicit env to package manager child process', async () => {
    const child = new EventEmitter();
    mocks.spawn.mockReturnValue(child);
    mocks.resolveCommandForSpawn.mockResolvedValue({
      command: 'npm',
      args: ['install', '--ignore-scripts']
    });

    const result = runPackageManager('npm', ['install', '--ignore-scripts'], process.cwd(), {
      env: { PATH: 'safe-path', HOME: 'sandbox-home' }
    });
    await new Promise((resolve) => setImmediate(resolve));
    child.emit('close', 0);

    await expect(result).resolves.toBe(0);
    expect(mocks.resolveCommandForSpawn).toHaveBeenCalledWith('npm', ['install', '--ignore-scripts'], {
      env: { PATH: 'safe-path', HOME: 'sandbox-home' }
    });
    expect(mocks.spawn).toHaveBeenCalledWith(
      'npm',
      ['install', '--ignore-scripts'],
      expect.objectContaining({
        env: { PATH: 'safe-path', HOME: 'sandbox-home' }
      })
    );
  });
});
