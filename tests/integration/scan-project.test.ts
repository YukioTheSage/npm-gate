import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { scanProject } from '../../src/core/engine.js';
import type { RegistryClient, SourceVerifier } from '../../src/core/types.js';

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

  test('does not fan out registry metadata for lockfile-only transitive packages', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-large-lockfile-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ private: true, dependencies: { direct: '1.0.0' } })
    );
    await writeFile(
      join(cwd, 'pnpm-lock.yaml'),
      [
        "lockfileVersion: '9.0'",
        'packages:',
        '  direct@1.0.0:',
        '    resolution: {integrity: sha512-fixture}',
        ...Array.from({ length: 350 }, (_, index) =>
          [
            `  transitive-${index}@1.0.0:`,
            '    resolution: {integrity: sha512-fixture}'
          ].join('\n')
        )
      ].join('\n')
    );
    const metadataCalls: string[] = [];
    const boundedRegistry: RegistryClient = {
      async getPackageMetadata(name: string) {
        metadataCalls.push(name);
        if (name.startsWith('transitive-')) {
          throw new Error(`unexpected metadata lookup for ${name}`);
        }
        return {
          name,
          versions: {
            '1.0.0': {
              name,
              version: '1.0.0',
              repository: { type: 'git', url: 'https://example.test/direct.git' }
            }
          },
          time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion(_name: string, range: string | undefined) {
        return range ?? '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry: boundedRegistry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings.map((finding) => finding.package)).toEqual(['direct']);
    expect(metadataCalls).toEqual(['direct']);
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

  test('emergency policy mode blocks denylisted direct dependencies', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-emergency-denylist-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ private: true, dependencies: { 'known-bad': '1.0.0' } })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({
        policyMode: 'emergency',
        emergencyDenylist: [
          { package: 'known-bad', versions: ['1.0.0'], reason: 'active incident' }
        ]
      })
    );

    const emergencyRegistry: RegistryClient = {
      async getPackageMetadata(name: string) {
        return {
          name,
          versions: {
            '1.0.0': {
              name,
              version: '1.0.0',
              repository: { type: 'git', url: 'https://example.test/known-bad.git' }
            }
          },
          time: { '1.0.0': '2026-01-02T00:00:00.000Z' },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion() {
        return '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry: emergencyRegistry,
      env: { NPM_GATE_MODE: 'warn', NPM_GATE_POLICY_MODE: 'emergency' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.policyMode).toBe('emergency');
    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'known-bad',
          decision: 'block',
          riskCategory: 'emergency_denylist_risk'
        })
      ])
    );
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

  test('runs configured source verification only for matching package rules', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-source-verification-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({
        private: true,
        dependencies: { verified: '1.0.0', skipped: '1.0.0' }
      })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({
        policyMode: 'strict',
        sourceVerification: {
          enabled: true,
          rules: [
            {
              package: 'verified',
              repository: 'owner/verified',
              tagTemplate: 'v{version}',
              commit: 'expected',
              required: true
            }
          ]
        }
      })
    );
    const calls: Array<{ repository: string; tag?: string; commit?: string }> = [];
    const sourceVerifier: SourceVerifier = {
      async resolveTagCommit(repository, tag) {
        calls.push({ repository, tag });
        return 'actual';
      },
      async hasCommit(repository, commit) {
        calls.push({ repository, commit });
        return commit === 'expected';
      }
    };
    const sourceRegistry: RegistryClient = {
      async getPackageMetadata(name: string) {
        return {
          name,
          versions: {
            '1.0.0': {
              name,
              version: '1.0.0',
              repository: { type: 'git', url: `https://github.com/owner/${name}.git` }
            }
          },
          time: { '1.0.0': '2026-01-02T00:00:00.000Z' },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion() {
        return '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry: sourceRegistry,
      sourceVerifier,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(calls).toEqual([
      { repository: 'owner/verified', tag: 'v1.0.0' },
      { repository: 'owner/verified', commit: 'expected' }
    ]);
    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'verified',
          decision: 'block',
          matchedSignals: expect.arrayContaining(['source-tag-commit-mismatch'])
        })
      ])
    );
    expect(report.findings.find((finding) => finding.package === 'skipped')?.matchedSignals).not.toContain(
      'source-tag-commit-mismatch'
    );
  });

  test('propagates package-lock dependency paths into transitive lifecycle findings', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-lockfile-path-'));
    await writeFile(
      join(cwd, 'package-lock.json'),
      JSON.stringify({
        name: 'root-app',
        version: '0.0.0',
        lockfileVersion: 3,
        packages: {
          '': { name: 'root-app', version: '0.0.0' },
          'node_modules/parent': { version: '2.0.0' },
          'node_modules/parent/node_modules/child': { version: '3.0.0' }
        }
      })
    );

    const pathRegistry: RegistryClient = {
      async getPackageMetadata(name: string) {
        return {
          name,
          versions: {
            '3.0.0': {
              name,
              version: '3.0.0',
              scripts: name === 'child' ? { postinstall: 'node install.js' } : undefined,
              repository: { type: 'git', url: `https://example.test/${name}.git` }
            },
            '2.0.0': {
              name,
              version: '2.0.0',
              repository: { type: 'git', url: `https://example.test/${name}.git` }
            }
          },
          time: {
            '2.0.0': '2026-01-02T00:00:00.000Z',
            '3.0.0': '2026-01-02T00:00:00.000Z'
          },
          'dist-tags': { latest: name === 'child' ? '3.0.0' : '2.0.0' }
        };
      },
      async resolveVersion(_name, range) {
        return range ?? '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry: pathRegistry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'child',
          decision: 'block',
          dependencyPath: ['root-app@0.0.0', 'parent@2.0.0', 'child@3.0.0']
        })
      ])
    );
  });

  test('reports project source CDN findings as project-level runtime risk', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-project-runtime-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ private: true, dependencies: {} })
    );
    await writeFile(
      join(cwd, 'index.html'),
      '<script src="https://cdn.example/lottie-player@latest/index.js"></script>'
    );

    const report = await scanProject({
      cwd,
      registry,
      env: { NPM_GATE_MODE: 'warn' },
      policyMode: 'strict',
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'project:runtime-sources',
          decision: 'block',
          riskCategory: 'frontend_runtime_risk',
          matchedSignals: expect.arrayContaining(['project-cdn-latest'])
        })
      ])
    );
  });
});
