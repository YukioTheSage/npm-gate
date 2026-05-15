import { describe, expect, test } from 'vitest';
import {
  normalizeGitHubRepository,
  sourceVerificationSignals
} from '../../src/analyzers/source-verification-analyzer.js';
import type { SourceVerifier } from '../../src/core/types.js';

const verifier: SourceVerifier = {
  async resolveTagCommit(repository: string, tag: string) {
    if (repository === 'owner/pkg' && tag === 'v1.0.0') return 'abc123';
    if (repository === 'owner/pkg' && tag === 'v1.0.1') return 'def456';
    return undefined;
  },
  async hasCommit(repository: string, commit: string) {
    return repository === 'owner/pkg' && ['abc123', 'def456'].includes(commit);
  },
  async fetchFile(repository: string, ref: string, path: string) {
    if (repository !== 'owner/pkg' || ref !== 'abc123' || path !== 'package.json') {
      return undefined;
    }
    return JSON.stringify({
      name: 'pkg',
      version: '1.0.0',
      scripts: { test: 'vitest' },
      dependencies: { leftpad: '1.0.0' },
      repository: { type: 'git', url: 'https://github.com/owner/pkg.git' }
    });
  }
};

describe('source verification analyzer', () => {
  test('normalizes supported GitHub repository forms', () => {
    expect(normalizeGitHubRepository('owner/pkg')).toBe('owner/pkg');
    expect(normalizeGitHubRepository('https://github.com/owner/pkg')).toBe('owner/pkg');
    expect(normalizeGitHubRepository('https://github.com/owner/pkg.git')).toBe('owner/pkg');
  });

  test('does not emit findings when configured tag and commit match', async () => {
    await expect(
      sourceVerificationSignals({
        packageName: 'pkg',
        version: '1.0.0',
        rule: {
          package: 'pkg',
          repository: 'https://github.com/owner/pkg.git',
          tagTemplate: 'v{version}',
          commit: 'abc123',
          required: true
        },
        verifier
      })
    ).resolves.toEqual([]);
  });

  test('flags missing tags, missing commits, and tag commit mismatches', async () => {
    const missingTag = await sourceVerificationSignals({
      packageName: 'pkg',
      version: '9.9.9',
      rule: {
        package: 'pkg',
        repository: 'owner/pkg',
        tagTemplate: 'v{version}',
        required: true
      },
      verifier
    });
    const missingCommit = await sourceVerificationSignals({
      packageName: 'pkg',
      version: '1.0.0',
      rule: {
        package: 'pkg',
        repository: 'owner/pkg',
        commit: 'missing',
        required: true
      },
      verifier
    });
    const mismatch = await sourceVerificationSignals({
      packageName: 'pkg',
      version: '1.0.1',
      rule: {
        package: 'pkg',
        repository: 'owner/pkg',
        tagTemplate: 'v{version}',
        commit: 'abc123',
        required: true
      },
      verifier
    });

    expect(missingTag.map((signal) => signal.id)).toEqual(['source-tag-missing']);
    expect(missingCommit.map((signal) => signal.id)).toEqual(['source-commit-missing']);
    expect(mismatch.map((signal) => signal.id)).toEqual(['source-tag-commit-mismatch']);
    expect(mismatch[0]?.canOverride).toBe(false);
  });

  test('marks optional verification failures for manual review', async () => {
    const signals = await sourceVerificationSignals({
      packageName: 'pkg',
      version: '9.9.9',
      rule: {
        package: 'pkg',
        repository: 'owner/pkg',
        tagTemplate: 'v{version}',
        required: false
      },
      verifier
    });

    expect(signals[0]).toMatchObject({
      id: 'source-tag-missing',
      manualReview: true,
      canOverride: true
    });
  });

  test('reports source verification client failures without leaking transport details into decisions', async () => {
    const failingVerifier: SourceVerifier = {
      async resolveTagCommit() {
        throw new Error('rate limited');
      },
      async hasCommit() {
        return false;
      }
    };

    const signals = await sourceVerificationSignals({
      packageName: 'pkg',
      version: '1.0.0',
      rule: {
        package: 'pkg',
        repository: 'owner/pkg',
        tagTemplate: 'v{version}',
        required: true
      },
      verifier: failingVerifier
    });

    expect(signals[0]).toMatchObject({
      id: 'source-verification-unavailable',
      canOverride: false
    });
  });

  test('compares published manifest against configured source manifest', async () => {
    const signals = await sourceVerificationSignals({
      packageName: 'pkg',
      version: '1.0.0',
      currentManifest: {
        name: 'pkg',
        version: '1.0.0',
        scripts: { postinstall: 'node install.js' },
        dependencies: { leftpad: '1.0.0', unexpected: '9.9.9' },
        repository: { type: 'git', url: 'https://github.com/owner/pkg.git' }
      },
      rule: {
        package: 'pkg',
        repository: 'owner/pkg',
        tagTemplate: 'v{version}',
        commit: 'abc123',
        packageJsonPath: 'package.json',
        required: true
      },
      verifier
    });

    expect(signals).toEqual([
      expect.objectContaining({
        id: 'source-manifest-mismatch',
        canOverride: false,
        matchedSignals: expect.arrayContaining(['scripts', 'dependencies'])
      })
    ]);
  });
});
