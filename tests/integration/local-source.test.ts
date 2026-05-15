import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp } from 'node:fs/promises';
import * as tar from 'tar';
import { describe, expect, test } from 'vitest';
import { evaluatePackages } from '../../src/core/engine.js';
import type { PackageCandidate } from '../../src/core/types.js';

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
): Promise<string> {
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
  return tarball;
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

describe('local source inspection', () => {
  test('allows clean local tarballs after static inspection', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-tar-clean-'));
    const source = await writePackage(cwd, 'clean-src', {
      name: 'clean-local',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const tarball = await packDirectory(cwd, source, 'clean-local-1.0.0.tgz');

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(tarball, 'local-tarball')]
    });

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toMatchObject({
      package: 'clean-local',
      version: '1.0.0',
      decision: 'allow'
    });
  });

  test('blocks local tarballs with lifecycle scripts', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-tar-script-'));
    const source = await writePackage(cwd, 'script-src', {
      name: 'script-local',
      version: '1.0.0',
      scripts: { postinstall: 'node postinstall.js' },
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const tarball = await packDirectory(cwd, source, 'script-local-1.0.0.tgz');

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(tarball, 'local-tarball')]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'script-local',
      decision: 'block',
      reasons: ['Lifecycle script detected: postinstall']
    });
  });

  test('blocks local tarballs without package manifests', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-tar-missing-'));
    const source = join(cwd, 'missing-src');
    await mkdir(source, { recursive: true });
    await writeFile(join(source, 'index.js'), 'console.log("fixture");', 'utf8');
    const tarball = await packDirectory(cwd, source, 'missing-manifest-1.0.0.tgz');

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(tarball, 'local-tarball')]
    });

    expect(report.findings[0]).toMatchObject({
      package: tarball,
      decision: 'block',
      reasons: ['Local package source is missing package.json']
    });
  });

  test('warns on suspicious files inside local tarballs', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-tar-suspicious-'));
    const source = await writePackage(
      cwd,
      'suspicious-src',
      {
        name: 'suspicious-local',
        version: '1.0.0',
        repository: { type: 'git', url: 'https://example.test/repo.git' }
      },
      {
        'scripts/install.sh': '#!/bin/sh\n'
      }
    );
    const tarball = await packDirectory(cwd, source, 'suspicious-local-1.0.0.tgz');

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(tarball, 'local-tarball')]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'suspicious-local',
      decision: 'warn',
      reasons: ['Shell or PowerShell script found: package/scripts/install.sh']
    });
  });

  test('allows clean local directories after package manifest inspection', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-dir-clean-'));
    const source = await writePackage(cwd, 'dir-src', {
      name: 'clean-directory',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(source, 'local-directory')]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'clean-directory',
      version: '1.0.0',
      decision: 'allow'
    });
  });

  test('blocks local directories with lifecycle scripts', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-dir-script-'));
    const source = await writePackage(cwd, 'dir-src', {
      name: 'script-directory',
      version: '1.0.0',
      scripts: { preinstall: 'node preinstall.js' },
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(source, 'local-directory')]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'script-directory',
      decision: 'block',
      reasons: ['Lifecycle script detected: preinstall']
    });
  });

  test('blocks missing local directories', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-local-dir-missing-'));
    const source = join(cwd, 'does-not-exist');

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(source, 'local-directory')]
    });

    expect(report.findings[0]).toMatchObject({
      package: source,
      decision: 'block',
      reasons: ['Unable to inspect local package source']
    });
  });

  test('blocks unsupported direct remote tarball URLs', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-tar-'));
    const spec = 'https://registry.example/pkg/-/pkg-1.0.0.tgz';

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(spec, 'remote-tarball-unsupported')]
    });

    expect(report.findings[0]).toMatchObject({
      package: spec,
      decision: 'block',
      reasons: ['Direct remote tarball host is not configured for inspection']
    });
  });

  test('warns on direct GitHub sources in local mode without cloning', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-git-warn-'));
    const spec = 'github:user/repo';

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      candidates: [localCandidate(spec, 'git')]
    });

    expect(report.findings[0]).toMatchObject({
      package: spec,
      decision: 'warn',
      reasons: ['Git dependency requested: github:user/repo']
    });
  });

  test('blocks direct GitHub sources under strict and CI modes', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-git-block-'));
    const spec = 'github:user/repo';

    const strictReport = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn' },
      strict: true,
      candidates: [localCandidate(spec, 'git')]
    });
    const ciReport = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'ci' },
      candidates: [localCandidate(spec, 'git')]
    });

    expect(strictReport.findings[0]).toMatchObject({ package: spec, decision: 'block' });
    expect(ciReport.findings[0]).toMatchObject({ package: spec, decision: 'block' });
  });
});
