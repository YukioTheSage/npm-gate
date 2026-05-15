import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { scanProject } from '../../src/core/engine.js';
import type { RegistryClient } from '../../src/core/types.js';

const registry: RegistryClient = {
  async getPackageMetadata(name: string) {
    return {
      name,
      versions: {
        '1.0.0': {
          name,
          version: '1.0.0',
          scripts:
            name === 'package-with-postinstall' ? { postinstall: 'node fixture.js' } : undefined,
          dist: {
            tarball: `https://registry.example/${name}/-/${name}-1.0.0.tgz`
          }
        }
      },
      time: {
        '1.0.0': '2026-05-13T00:00:00.000Z'
      },
      'dist-tags': { latest: '1.0.0' }
    };
  },
  async resolveVersion(_name: string, range: string | undefined) {
    return range ?? '1.0.0';
  }
};

describe('scanProject', () => {
  test('scans package manifests and lockfiles using mocked registry metadata', async () => {
    const report = await scanProject({
      cwd: 'tests/fixtures/projects/basic-project',
      registry,
      env: { NPM_GATE_MODE: 'ci' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings.map((finding) => finding.package)).toEqual(
      expect.arrayContaining(['clean-package', 'package-with-postinstall'])
    );
    expect(
      report.findings.find((finding) => finding.package === 'package-with-postinstall')?.decision
    ).toBe('block');
  });

  test('applies injected vulnerability advisories to scan decisions', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-advisory-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({
        private: true,
        dependencies: { reviewed: '1.0.0' }
      })
    );

    const advisoryRegistry: RegistryClient = {
      async getPackageMetadata(name: string) {
        return {
          name,
          versions: {
            '0.9.0': { name, version: '0.9.0', repository: { type: 'git', url: 'test' } },
            '1.0.0': { name, version: '1.0.0', repository: { type: 'git', url: 'test' } }
          },
          time: {
            '0.9.0': '2026-01-01T00:00:00.000Z',
            '1.0.0': '2026-01-02T00:00:00.000Z'
          },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion(_name: string, range: string | undefined) {
        return range ?? '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry: advisoryRegistry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z'),
      advisories: [
        {
          name: 'reviewed',
          versions: ['1.0.0'],
          type: 'vulnerability',
          severity: 'high',
          summary: 'Injected audit advisory'
        }
      ]
    });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({
      package: 'reviewed',
      decision: 'warn',
      reasons: ['vulnerability advisory matched: Injected audit advisory']
    });
  });

  test('blocks injected malicious advisories', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-malicious-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({
        private: true,
        dependencies: { malicious: '1.0.0' }
      })
    );

    const advisoryRegistry: RegistryClient = {
      async getPackageMetadata(name: string) {
        return {
          name,
          versions: {
            '0.9.0': { name, version: '0.9.0', repository: { type: 'git', url: 'test' } },
            '1.0.0': { name, version: '1.0.0', repository: { type: 'git', url: 'test' } }
          },
          time: {
            '0.9.0': '2026-01-01T00:00:00.000Z',
            '1.0.0': '2026-01-02T00:00:00.000Z'
          },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion(_name: string, range: string | undefined) {
        return range ?? '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry: advisoryRegistry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z'),
      advisories: [
        {
          name: 'malicious',
          versions: ['1.0.0'],
          type: 'malicious',
          severity: 'critical',
          summary: 'Injected malicious advisory'
        }
      ]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'malicious',
      decision: 'block',
      canOverride: false,
      reasons: ['malicious advisory matched: Injected malicious advisory']
    });
  });
});
