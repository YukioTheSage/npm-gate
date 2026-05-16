import { beforeEach, describe, expect, test, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  runCommand: vi.fn()
}));

vi.mock('../../src/utils/exec.js', () => ({
  runCommand: mocks.runCommand
}));

const { NpmAuditSignaturesVerifier } = await import(
  '../../src/verification/npm-audit-signatures-verifier.js'
);

describe('npm audit signatures verifier', () => {
  beforeEach(() => {
    mocks.runCommand.mockReset();
  });

  test('treats successful audit signatures output as verified and caches by cwd', async () => {
    mocks.runCommand.mockResolvedValue({
      exitCode: 0,
      stdout: JSON.stringify({ signatures: [{ status: 'verified' }] }),
      stderr: ''
    });
    const verifier = new NpmAuditSignaturesVerifier();

    await expect(
      verifier.verify({ cwd: 'fixture', packageName: 'left-pad', version: '1.3.0' })
    ).resolves.toMatchObject({ status: 'verified' });
    await expect(
      verifier.verify({ cwd: 'fixture', packageName: 'right-pad', version: '1.0.0' })
    ).resolves.toMatchObject({ status: 'verified' });

    expect(mocks.runCommand).toHaveBeenCalledTimes(1);
  });

  test('returns unavailable when npm cannot be resolved', async () => {
    mocks.runCommand.mockResolvedValue({
      exitCode: 2,
      stdout: '',
      stderr: 'npm not found'
    });
    const verifier = new NpmAuditSignaturesVerifier();

    await expect(
      verifier.verify({ cwd: 'fixture', packageName: 'left-pad', version: '1.3.0' })
    ).resolves.toMatchObject({ status: 'unavailable' });
  });

  test('returns invalid for malformed verification JSON', async () => {
    mocks.runCommand.mockResolvedValue({
      exitCode: 0,
      stdout: '{bad json',
      stderr: ''
    });
    const verifier = new NpmAuditSignaturesVerifier();

    await expect(
      verifier.verify({ cwd: 'fixture', packageName: 'left-pad', version: '1.3.0' })
    ).resolves.toMatchObject({ status: 'invalid' });
  });
});
