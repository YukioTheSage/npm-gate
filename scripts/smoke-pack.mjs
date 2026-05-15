import { createServer } from 'node:http';
import { chmod, mkdtemp, mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { execFile } from 'node:child_process';
import * as tar from 'tar';

const root = process.cwd();

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      args,
      { ...options, shell: process.platform === 'win32', windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          reject(
            new Error(
              `${command} ${args.join(' ')} failed with code ${error.code ?? 'unknown'}\n${stdout}${stderr}`
            )
          );
          return;
        }
        resolve({ stdout, stderr });
      }
    );
  });
}

async function runGate(binPath, args, options = {}) {
  return run(binPath, args, options);
}

async function installPackedCli(packedCli, projectDir) {
  const packageDir = join(projectDir, 'node_modules', 'npm-gate');
  const binDir = join(projectDir, 'node_modules', '.bin');
  await mkdir(packageDir, { recursive: true });
  await mkdir(binDir, { recursive: true });
  await tar.x({ file: packedCli, cwd: packageDir, strip: 1 });
  await linkRuntimeDependencies(packageDir, projectDir);

  const shellShim = join(binDir, 'npm-gate');
  await writeFile(
    shellShim,
    '#!/usr/bin/env sh\nbasedir=$(dirname "$0")\nexec node "$basedir/../npm-gate/dist/index.js" "$@"\n',
    'utf8'
  );
  await chmod(shellShim, 0o755);

  await writeFile(
    join(binDir, 'npm-gate.cmd'),
    '@ECHO off\r\nnode "%~dp0\\..\\npm-gate\\dist\\index.js" %*\r\n',
    'utf8'
  );
}

async function linkRuntimeDependencies(packageDir, projectDir) {
  const manifest = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'));
  for (const dependencyName of Object.keys(manifest.dependencies ?? {})) {
    const source = join(root, 'node_modules', dependencyName);
    const target = join(projectDir, 'node_modules', dependencyName);
    await mkdir(dirname(target), { recursive: true });
    await symlink(source, target, process.platform === 'win32' ? 'junction' : 'dir');
  }
}

async function packFixture(rootDir, name, manifest, files = {}) {
  const source = join(rootDir, `${name}-src`);
  await mkdir(source, { recursive: true });
  await writeFile(join(source, 'package.json'), JSON.stringify(manifest), 'utf8');
  for (const [path, content] of Object.entries(files)) {
    const target = join(source, path);
    await mkdir(join(target, '..'), { recursive: true });
    await writeFile(target, content);
  }
  const tarball = join(rootDir, `${name}-1.0.0.tgz`);
  await tar.c(
    {
      cwd: source,
      gzip: true,
      file: tarball,
      portable: true,
      prefix: 'package/'
    },
    ['.']
  );
  return tarball;
}

async function startTarballServer(tarballPath) {
  const tarball = await readFile(tarballPath);
  const server = createServer((_request, response) => {
    response.statusCode = 200;
    response.setHeader('content-type', 'application/octet-stream');
    response.end(tarball);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Smoke HTTP server did not bind');
  const baseUrl = `http://127.0.0.1:${address.port}/`;
  return { server, baseUrl, tarballUrl: `${baseUrl}pkg/-/pkg-1.0.0.tgz` };
}

function assertAllow(stdout, label) {
  const report = JSON.parse(stdout);
  const finding = report.findings?.[0];
  if (finding?.decision !== 'allow') {
    throw new Error(`${label} expected allow, got ${JSON.stringify(finding, null, 2)}`);
  }
}

const workspace = await mkdtemp(join(tmpdir(), 'npm-gate-smoke-'));
const packDir = join(workspace, 'pack');
const projectDir = join(workspace, 'project');
await mkdir(packDir, { recursive: true });
await mkdir(projectDir, { recursive: true });

await run('pnpm', ['pack', '--pack-destination', packDir], { cwd: root });
const packedName = (await readdir(packDir)).find((name) => name.endsWith('.tgz'));
if (!packedName) throw new Error('pnpm pack did not create a tarball');
const packedCli = join(packDir, packedName);

await writeFile(
  join(projectDir, 'package.json'),
  JSON.stringify({ private: true, type: 'module' }),
  'utf8'
);
await installPackedCli(packedCli, projectDir);

const binPath = join(
  projectDir,
  'node_modules',
  '.bin',
  process.platform === 'win32' ? 'npm-gate.cmd' : 'npm-gate'
);
const fixtureManifest = {
  name: 'smoke-clean',
  version: '1.0.0',
  repository: { type: 'git', url: 'https://example.test/repo.git' }
};
const localTarball = await packFixture(workspace, 'smoke-clean', fixtureManifest, {
  'index.js': 'module.exports = 1;\n'
});

const localReport = await runGate(binPath, ['install', localTarball, '--dry-run', '--json'], {
  cwd: projectDir
});
assertAllow(localReport.stdout, 'local tarball smoke');

const served = await startTarballServer(localTarball);
try {
  const remoteReport = await runGate(
    binPath,
    ['install', served.tarballUrl, '--dry-run', '--json'],
    {
      cwd: projectDir,
      env: { ...process.env, npm_config_registry: served.baseUrl, NPM_GATE_MODE: 'warn' }
    }
  );
  assertAllow(remoteReport.stdout, 'remote tarball smoke');
} finally {
  await new Promise((resolve) => served.server.close(() => resolve()));
}

process.stdout.write(`Pack smoke passed with ${packedName}\n`);
