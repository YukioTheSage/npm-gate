import { Command } from 'commander';
import { afterEach, describe, expect, test, vi } from 'vitest';

const { registerExplainCommand } = await import('../../src/cli/commands/explain.js');

function makeProgram(): Command {
  const program = new Command();
  program.exitOverride();
  registerExplainCommand(program);
  return program;
}

describe('explain command', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  test('explains finding ids with response guidance', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);

    await makeProgram().parseAsync(['explain', 'workflow-cache-poisoning-risk:ci.yml'], {
      from: 'user'
    });

    expect(stdout).toHaveBeenCalledWith(expect.stringContaining('workflow-cache-poisoning-risk'));
    expect(stdout).toHaveBeenCalledWith(expect.stringContaining('Do not install or release'));
    expect(stdout).toHaveBeenCalledWith(expect.stringContaining('rotate reachable tokens'));
    expect(process.exitCode).toBe(0);
  });
});
