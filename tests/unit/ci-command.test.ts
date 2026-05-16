import { Command } from 'commander';
import { afterEach, describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  scanProject: vi.fn(),
  renderConsoleReport: vi.fn(() => 'console report\n')
}));

vi.mock('../../src/core/engine.js', () => ({
  scanProject: mocks.scanProject
}));

vi.mock('../../src/reporting/console-reporter.js', () => ({
  renderConsoleReport: mocks.renderConsoleReport
}));

const { registerCiCommand } = await import('../../src/cli/commands/ci.js');

function makeProgram(): Command {
  const program = new Command();
  program.exitOverride();
  registerCiCommand(program);
  return program;
}

describe('ci command', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    mocks.scanProject.mockReset();
    mocks.renderConsoleReport.mockClear();
    process.exitCode = undefined;
    delete process.env.NPM_GATE_MODE;
  });

  test('runs production-grade scan without delegating to npm ci', async () => {
    mocks.scanProject.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'ci',
      configSource: 'default',
      findings: [
        {
          id: 'clean:fixture@1.0.0',
          package: 'fixture',
          version: '1.0.0',
          decision: 'allow',
          severity: 'info',
          score: 0,
          reasons: ['No policy issues detected'],
          evidence: [],
          remediation: [],
          canOverride: false
        }
      ],
      summary: { allow: 1, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['ci', '--json'], { from: 'user' });

    expect(mocks.scanProject).toHaveBeenCalledWith(
      expect.objectContaining({
        env: expect.objectContaining({ NPM_GATE_MODE: 'ci' }),
        strict: true,
        production: true,
        policyMode: 'strict'
      })
    );
    expect(process.exitCode).toBe(0);
  });

  test('release audit enables deep transitive tarball inspection', async () => {
    mocks.scanProject.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'ci',
      policyMode: 'strict',
      configSource: 'default',
      findings: [],
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['ci', '--release-audit', '--json'], { from: 'user' });

    expect(mocks.scanProject).toHaveBeenCalledWith(
      expect.objectContaining({
        analyzeTarballs: true,
        deepTarballInspection: true,
        production: true,
        policyMode: 'strict'
      })
    );
    expect(process.exitCode).toBe(0);
  });

  test('passes pnpm and yarn lockfile baselines into project scan', async () => {
    mocks.scanProject.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'ci',
      policyMode: 'strict',
      configSource: 'default',
      findings: [],
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(
      [
        'ci',
        '--previous-pnpm-lock',
        '../baseline/pnpm-lock.yaml',
        '--previous-yarn-lock',
        '../baseline/yarn.lock',
        '--json'
      ],
      { from: 'user' }
    );

    expect(mocks.scanProject).toHaveBeenCalledWith(
      expect.objectContaining({
        previousPnpmLockPath: '../baseline/pnpm-lock.yaml',
        previousYarnLockPath: '../baseline/yarn.lock'
      })
    );
  });
});
