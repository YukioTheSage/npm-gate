import { createServer, type Server } from 'node:http';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp } from 'node:fs/promises';
import * as tar from 'tar';
import { afterEach, describe, expect, test } from 'vitest';
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

function remoteCandidate(spec: string): PackageCandidate {
  return {
    name: spec,
    requested: spec,
    spec,
    source: 'cli',
    sourceType: 'remote-tarball'
  };
}

async function startTarballServer(
  tarball: Buffer,
  statusCode = 200
): Promise<{ server: Server; baseUrl: string; tarballUrl: string }> {
  const server = createServer((_request, response) => {
    response.statusCode = statusCode;
    if (statusCode === 200) {
      response.setHeader('content-type', 'application/octet-stream');
      response.end(tarball);
    } else {
      response.end('not found');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('HTTP fixture did not bind');
  const baseUrl = `http://127.0.0.1:${address.port}/`;
  return { server, baseUrl, tarballUrl: `${baseUrl}pkg/-/pkg-1.0.0.tgz` };
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))
  );
});

describe('remote tarball inspection', () => {
  test('allows clean tarballs from the configured registry', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-clean-'));
    const source = await writePackage(cwd, 'clean-src', {
      name: 'remote-clean',
      version: '1.0.0',
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const tarball = await packDirectory(cwd, source, 'remote-clean-1.0.0.tgz');
    const served = await startTarballServer(await readFile(tarball));
    servers.push(served.server);

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [remoteCandidate(served.tarballUrl)]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'remote-clean',
      version: '1.0.0',
      decision: 'allow',
      reasons: ['No policy issues detected']
    });
  });

  test('blocks configured-registry tarballs with lifecycle scripts', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-script-'));
    const source = await writePackage(cwd, 'script-src', {
      name: 'remote-script',
      version: '1.0.0',
      scripts: { postinstall: 'node postinstall.js' },
      repository: { type: 'git', url: 'https://example.test/repo.git' }
    });
    const tarball = await packDirectory(cwd, source, 'remote-script-1.0.0.tgz');
    const served = await startTarballServer(await readFile(tarball));
    servers.push(served.server);

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [remoteCandidate(served.tarballUrl)]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'remote-script',
      decision: 'block',
      reasons: ['Lifecycle script detected: postinstall']
    });
  });

  test('warns on suspicious files inside configured-registry tarballs', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-suspicious-'));
    const source = await writePackage(
      cwd,
      'suspicious-src',
      {
        name: 'remote-suspicious',
        version: '1.0.0',
        repository: { type: 'git', url: 'https://example.test/repo.git' }
      },
      { 'scripts/install.sh': '#!/bin/sh\n' }
    );
    const tarball = await packDirectory(cwd, source, 'remote-suspicious-1.0.0.tgz');
    const served = await startTarballServer(await readFile(tarball));
    servers.push(served.server);

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [remoteCandidate(served.tarballUrl)]
    });

    expect(report.findings[0]).toMatchObject({
      package: 'remote-suspicious',
      decision: 'warn',
      reasons: ['Shell or PowerShell script found: package/scripts/install.sh']
    });
  });

  test('blocks configured-registry tarballs without package manifests', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-missing-'));
    const source = join(cwd, 'missing-src');
    await mkdir(source, { recursive: true });
    await writeFile(join(source, 'index.js'), 'console.log("fixture");', 'utf8');
    const tarball = await packDirectory(cwd, source, 'remote-missing-1.0.0.tgz');
    const served = await startTarballServer(await readFile(tarball));
    servers.push(served.server);

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [remoteCandidate(served.tarballUrl)]
    });

    expect(report.findings[0]).toMatchObject({
      package: served.tarballUrl,
      decision: 'block',
      reasons: ['Remote tarball package.json is missing']
    });
  });

  test('blocks configured-registry tarballs with invalid package manifests', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-invalid-'));
    const source = join(cwd, 'invalid-src');
    await mkdir(source, { recursive: true });
    await writeFile(join(source, 'package.json'), '{ invalid json', 'utf8');
    const tarball = await packDirectory(cwd, source, 'remote-invalid-1.0.0.tgz');
    const served = await startTarballServer(await readFile(tarball));
    servers.push(served.server);

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [remoteCandidate(served.tarballUrl)]
    });

    expect(report.findings[0]).toMatchObject({
      package: served.tarballUrl,
      decision: 'block',
      reasons: ['Remote tarball package.json is invalid']
    });
  });

  test('blocks arbitrary remote tarball hosts', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-host-'));
    const spec = 'https://downloads.example.test/pkg/-/pkg-1.0.0.tgz';

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: 'https://registry.npmjs.org/' },
      candidates: [remoteCandidate(spec)]
    });

    expect(report.findings[0]).toMatchObject({
      package: spec,
      decision: 'block',
      reasons: ['Direct remote tarball host is not configured for inspection']
    });
  });

  test('blocks fetch failures from configured registries', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-remote-fetch-'));
    const served = await startTarballServer(Buffer.from('not a tarball'), 404);
    servers.push(served.server);

    const report = await evaluatePackages({
      cwd,
      env: { NPM_GATE_MODE: 'warn', npm_config_registry: served.baseUrl },
      candidates: [remoteCandidate(served.tarballUrl)]
    });

    expect(report.findings[0]).toMatchObject({
      package: served.tarballUrl,
      decision: 'block',
      reasons: ['Unable to inspect remote package tarball']
    });
  });
});
