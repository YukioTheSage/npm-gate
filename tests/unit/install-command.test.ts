import { Command } from 'commander';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  evaluatePackages: vi.fn(),
  scanProject: vi.fn(),
  resolvePackageManager: vi.fn(),
  runPackageManager: vi.fn(),
  renderConsoleReport: vi.fn(() => 'console report\n')
}));

vi.mock('../../src/core/engine.js', () => ({
  evaluatePackages: mocks.evaluatePackages,
  scanProject: mocks.scanProject
}));

vi.mock('../../src/wrappers/package-manager-runner.js', () => ({
  resolvePackageManager: mocks.resolvePackageManager,
  runPackageManager: mocks.runPackageManager
}));

vi.mock('../../src/reporting/console-reporter.js', () => ({
  renderConsoleReport: mocks.renderConsoleReport
}));

const { registerInstallCommands } = await import('../../src/cli/commands/install.js');

function makeProgram(): Command {
  const program = new Command();
  program.exitOverride();
  registerInstallCommands(program);
  return program;
}

describe('install command delegation', () => {
  beforeEach(() => {
    mocks.evaluatePackages.mockReset();
    mocks.scanProject.mockReset();
    mocks.resolvePackageManager.mockReset();
    mocks.resolvePackageManager.mockResolvedValue('npm');
    mocks.runPackageManager.mockReset();
    mocks.renderConsoleReport.mockClear();
    process.exitCode = undefined;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('does not delegate blocked local tarballs to npm', async () => {
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      configSource: 'default',
      findings: [
        {
          id: 'lifecycle-script:fixture@1.0.0',
          package: 'fixture',
          version: '1.0.0',
          decision: 'block',
          severity: 'high',
          score: 80,
          reasons: ['Lifecycle script detected: postinstall'],
          evidence: [],
          remediation: [],
          canOverride: true
        }
      ],
      summary: { allow: 0, warn: 0, block: 1, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['install', './fixture.tgz'], { from: 'user' });

    expect(mocks.evaluatePackages).toHaveBeenCalledWith(
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceType: 'local-tarball',
            spec: './fixture.tgz'
          })
        ]
      })
    );
    expect(mocks.runPackageManager).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });

  test('delegates local warnings only when strict mode is not enabled', async () => {
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      configSource: 'default',
      findings: [
        {
          id: 'suspicious-script-file:fixture@1.0.0',
          package: 'fixture',
          version: '1.0.0',
          decision: 'warn',
          severity: 'medium',
          score: 20,
          reasons: ['Shell or PowerShell script found: package/scripts/install.sh'],
          evidence: [],
          remediation: [],
          canOverride: true
        }
      ],
      summary: { allow: 0, warn: 1, block: 0, suppressed: 0 }
    });
    mocks.runPackageManager.mockResolvedValue(0);
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['install', './fixture.tgz'], { from: 'user' });

    expect(mocks.runPackageManager).toHaveBeenCalledWith(
      'npm',
      ['install', './fixture.tgz'],
      process.cwd()
    );
    expect(process.exitCode).toBe(0);

    mocks.runPackageManager.mockClear();
    await makeProgram().parseAsync(['install', './fixture.tgz', '--strict'], { from: 'user' });

    expect(mocks.runPackageManager).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });

  test('delegates through the selected package manager after policy allows', async () => {
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
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
    mocks.runPackageManager.mockResolvedValue(0);
    mocks.resolvePackageManager.mockResolvedValueOnce('pnpm');
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['install', 'left-pad', '--package-manager', 'pnpm'], {
      from: 'user'
    });

    expect(mocks.resolvePackageManager).toHaveBeenCalledWith({
      cwd: process.cwd(),
      env: expect.any(Object),
      requested: 'pnpm'
    });
    expect(mocks.runPackageManager).toHaveBeenCalledWith(
      'pnpm',
      ['install', 'left-pad'],
      process.cwd()
    );
  });

  test('sandbox execute delegates with ignore scripts and scrubbed env after policy allows', async () => {
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      configSource: 'default',
      findings: [
        {
          id: 'clean:left-pad@1.3.0',
          package: 'left-pad',
          version: '1.3.0',
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
    mocks.runPackageManager.mockResolvedValue(0);
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['install', 'left-pad', '--sandbox-execute'], {
      from: 'user'
    });

    expect(mocks.runPackageManager).toHaveBeenCalledWith(
      'npm',
      ['install', 'left-pad', '--ignore-scripts'],
      process.cwd(),
      expect.objectContaining({
        env: expect.objectContaining({ HOME: expect.any(String), USERPROFILE: expect.any(String) })
      })
    );
    expect(mocks.runPackageManager.mock.calls[0]?.[3]?.env.NPM_TOKEN).toBeUndefined();
  });

  test('passes remote tarball candidates into evaluation', async () => {
    const spec = 'https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz';
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
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

    await makeProgram().parseAsync(['install', spec, '--dry-run'], { from: 'user' });

    expect(mocks.evaluatePackages).toHaveBeenCalledWith(
      expect.objectContaining({
        candidates: [
          expect.objectContaining({
            sourceType: 'remote-tarball',
            spec
          })
        ]
      })
    );
    expect(mocks.runPackageManager).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(0);
  });

  test('passes explicit policy mode into install evaluation', async () => {
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      policyMode: 'emergency',
      configSource: 'default',
      findings: [],
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['install', 'left-pad', '--dry-run', '--policy-mode', 'emergency'], {
      from: 'user'
    });

    expect(mocks.evaluatePackages).toHaveBeenCalledWith(
      expect.objectContaining({ policyMode: 'emergency' })
    );
  });

  test('does not honor NPM_GATE_MODE=off in CI', async () => {
    const originalMode = process.env.NPM_GATE_MODE;
    const originalCi = process.env.CI;
    process.env.NPM_GATE_MODE = 'off';
    process.env.CI = 'true';
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    try {
      await expect(
        makeProgram().parseAsync(['install', 'left-pad'], { from: 'user' })
      ).rejects.toThrow(/NPM_GATE_MODE=off is forbidden/);

      expect(mocks.runPackageManager).not.toHaveBeenCalled();
    } finally {
      if (originalMode === undefined) {
        delete process.env.NPM_GATE_MODE;
      } else {
        process.env.NPM_GATE_MODE = originalMode;
      }
      if (originalCi === undefined) {
        delete process.env.CI;
      } else {
        process.env.CI = originalCi;
      }
    }
  });

  test('strict policy mode blocks manual review findings before delegation', async () => {
    mocks.evaluatePackages.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      policyMode: 'strict',
      configSource: 'default',
      findings: [
        {
          id: 'dependency-delta:fixture@1.0.1',
          package: 'fixture',
          version: '1.0.1',
          decision: 'manual_review',
          severity: 'medium',
          score: 45,
          reasons: ['Patch release added a new dependency'],
          evidence: [],
          remediation: ['Review the dependency delta before installing'],
          canOverride: true
        }
      ],
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['install', 'fixture', '--policy-mode', 'strict'], {
      from: 'user'
    });

    expect(mocks.runPackageManager).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
});
