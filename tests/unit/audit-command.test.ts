import { Command } from 'commander';
import { afterEach, describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  runCommand: vi.fn(),
  scanProject: vi.fn(),
  renderConsoleReport: vi.fn(() => 'console report\n')
}));

vi.mock('../../src/utils/exec.js', () => ({
  runCommand: mocks.runCommand
}));

vi.mock('../../src/core/engine.js', () => ({
  scanProject: mocks.scanProject
}));

vi.mock('../../src/reporting/console-reporter.js', () => ({
  renderConsoleReport: mocks.renderConsoleReport
}));

const { registerAuditCommand } = await import('../../src/cli/commands/audit.js');

describe('audit command', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    mocks.runCommand.mockReset();
    mocks.scanProject.mockReset();
    mocks.renderConsoleReport.mockClear();
    process.exitCode = undefined;
  });

  test('passes parsed npm audit advisories into scanProject', async () => {
    mocks.runCommand.mockResolvedValue({
      exitCode: 1,
      stdout: JSON.stringify({
        vulnerabilities: {
          lodash: {
            name: 'lodash',
            severity: 'high',
            title: 'Synthetic audit fixture',
            range: '<4.17.21'
          }
        }
      }),
      stderr: ''
    });
    mocks.scanProject.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      configSource: 'default',
      findings: [],
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    const program = new Command();
    program.exitOverride();
    registerAuditCommand(program);

    await program.parseAsync(['audit', '--json'], { from: 'user' });

    expect(mocks.scanProject).toHaveBeenCalledWith(
      expect.objectContaining({
        advisories: [
          {
            name: 'lodash',
            versions: ['<4.17.21'],
            type: 'vulnerability',
            severity: 'high',
            summary: 'Synthetic audit fixture'
          }
        ]
      })
    );
  });
});
