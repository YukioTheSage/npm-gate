import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { scanProject } from '../../src/core/engine.js';
import type { IntelligenceClient, RegistryClient } from '../../src/core/types.js';

const registry: RegistryClient = {
  async getPackageMetadata(name: string) {
    return {
      name,
      versions: {
        '0.9.0': {
          name,
          version: '0.9.0',
          repository: { type: 'git', url: 'https://example.test/repo.git' }
        },
        '1.0.0': {
          name,
          version: '1.0.0',
          repository: { type: 'git', url: 'https://example.test/repo.git' }
        }
      },
      time: {
        '0.9.0': '2025-12-01T00:00:00.000Z',
        '1.0.0': '2026-01-01T00:00:00.000Z'
      },
      'dist-tags': { latest: '1.0.0' }
    };
  },
  async resolveVersion() {
    return '1.0.0';
  }
};

describe('intelligence sources', () => {
  test('maps OSV query results into advisory-backed scan decisions', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-osv-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { risky: '1.0.0' } })
    );
    const intelligence: IntelligenceClient = {
      async queryVulnerabilities(packages) {
        expect(packages).toEqual([{ name: 'risky', version: '1.0.0' }]);
        return [
          {
            name: 'risky',
            versions: ['1.0.0'],
            type: 'vulnerability',
            severity: 'high',
            summary: 'OSV GHSA fixture'
          }
        ];
      }
    };

    const report = await scanProject({
      cwd,
      registry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z'),
      intelligence
    });

    expect(report.findings[0]).toMatchObject({
      package: 'risky',
      decision: 'warn',
      reasons: ['vulnerability advisory matched: OSV GHSA fixture']
    });
  });

  test('required intelligence sources fail closed in CI when unavailable', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-required-intel-'));
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { reviewed: '1.0.0' } })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({ requiredIntelligenceSources: ['osv'] })
    );

    const report = await scanProject({
      cwd,
      registry,
      env: { NPM_GATE_MODE: 'ci' },
      now: new Date('2026-05-14T00:00:00.000Z'),
      intelligence: {
        async queryVulnerabilities() {
          throw new Error('OSV unavailable');
        }
      }
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'intelligence:osv',
          decision: 'block',
          reasons: ['Required intelligence source is unavailable: osv']
        })
      ])
    );
  });
});
