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

const { registerEmergencyCommand } = await import('../../src/cli/commands/emergency.js');

function makeProgram(): Command {
  const program = new Command();
  program.exitOverride();
  registerEmergencyCommand(program);
  return program;
}

describe('emergency command', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    mocks.scanProject.mockReset();
    mocks.renderConsoleReport.mockClear();
    process.exitCode = undefined;
  });

  test('runs an emergency-mode scan with strict failure behavior', async () => {
    mocks.scanProject.mockResolvedValue({
      startedAt: '2026-05-14T00:00:00.000Z',
      toolVersion: '0.1.0',
      mode: 'warn',
      policyMode: 'emergency',
      configSource: 'default',
      findings: [],
      summary: { allow: 0, warn: 0, block: 0, suppressed: 0 }
    });
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['emergency', '--json'], { from: 'user' });

    expect(mocks.scanProject).toHaveBeenCalledWith(
      expect.objectContaining({
        strict: true,
        policyMode: 'emergency',
        analyzeTarballs: true
      })
    );
    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('"policyMode": "emergency"'));
  });
});
