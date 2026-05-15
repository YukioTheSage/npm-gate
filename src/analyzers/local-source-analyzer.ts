import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import * as tar from 'tar';
import type {
  PackageCandidate,
  PackageManifest,
  RegistryClient,
  RiskSignal
} from '../core/types.js';
import { lifecycleSignals } from './lifecycle-script-analyzer.js';
import { manifestBehaviorSignals } from './behavior-rules.js';
import { assertSafeTarPath } from './tarball-static-analyzer.js';
import { inspectTarballFile } from '../registry/tarball.js';

const MAX_MANIFEST_BYTES = 1024 * 1024;

export interface LocalSourceAnalysis {
  candidate: PackageCandidate;
  signals: RiskSignal[];
}

function stripLocalPrefix(spec: string): string {
  return spec.replace(/^(file:|link:)/, '');
}

function resolvedLocalPath(cwd: string, spec: string): string {
  const path = stripLocalPrefix(spec);
  return isAbsolute(path) ? path : resolve(cwd, path);
}

function normalizeTarPath(path: string): string {
  return path.replace(/\\/g, '/').replace(/\/\.\//g, '/');
}

function signal(
  id: string,
  score: number,
  severity: RiskSignal['severity'],
  message: string,
  evidenceType: string,
  value?: unknown
): RiskSignal {
  return {
    id,
    score,
    severity,
    message,
    evidence: [{ type: evidenceType, message, value }],
    remediation: [
      'Inspect the local package source manually before installation.',
      'Use a reviewed registry release when possible.'
    ],
    canOverride: false
  };
}

function localSourceUninspectable(candidate: PackageCandidate, error: unknown): RiskSignal {
  return signal(
    'local-source-uninspectable',
    70,
    'high',
    'Unable to inspect local package source',
    'local-source-error',
    {
      source: candidate.spec ?? candidate.requested ?? candidate.name,
      error: error instanceof Error ? error.message : String(error)
    }
  );
}

function localSourceManifestMissing(candidate: PackageCandidate): RiskSignal {
  return signal(
    'local-source-manifest-missing',
    70,
    'high',
    'Local package source is missing package.json',
    'local-source-manifest',
    candidate.resolvedPath ?? candidate.spec ?? candidate.requested ?? candidate.name
  );
}

function localTarballManifestInvalid(candidate: PackageCandidate, error: unknown): RiskSignal {
  return signal(
    'local-tarball-manifest-invalid',
    70,
    'high',
    'Local tarball package.json is invalid',
    'local-source-manifest',
    {
      source: candidate.resolvedPath ?? candidate.spec ?? candidate.requested ?? candidate.name,
      error: error instanceof Error ? error.message : String(error)
    }
  );
}

function unsupportedRemoteTarball(candidate: PackageCandidate): RiskSignal {
  return signal(
    'unsupported-remote-tarball',
    70,
    'high',
    'Direct remote tarball host is not configured for inspection',
    'dependency-spec',
    candidate.spec ?? candidate.requested ?? candidate.name
  );
}

function remoteTarballUninspectable(candidate: PackageCandidate, error: unknown): RiskSignal {
  return signal(
    'remote-tarball-uninspectable',
    70,
    'high',
    'Unable to inspect remote package tarball',
    'remote-tarball-error',
    {
      source: candidate.spec ?? candidate.requested ?? candidate.name,
      error: error instanceof Error ? error.message : String(error)
    }
  );
}

function remoteTarballManifestMissing(candidate: PackageCandidate): RiskSignal {
  return signal(
    'remote-tarball-manifest-missing',
    70,
    'high',
    'Remote tarball package.json is missing',
    'remote-tarball-manifest',
    candidate.spec ?? candidate.requested ?? candidate.name
  );
}

function remoteTarballManifestInvalid(candidate: PackageCandidate, error: unknown): RiskSignal {
  return signal(
    'remote-tarball-manifest-invalid',
    70,
    'high',
    'Remote tarball package.json is invalid',
    'remote-tarball-manifest',
    {
      source: candidate.spec ?? candidate.requested ?? candidate.name,
      error: error instanceof Error ? error.message : String(error)
    }
  );
}

async function readJsonManifest(path: string): Promise<PackageManifest> {
  const stats = await stat(path);
  if (stats.size > MAX_MANIFEST_BYTES) {
    throw new Error(`package.json exceeds ${MAX_MANIFEST_BYTES} byte manifest read limit`);
  }
  return JSON.parse(await readFile(path, 'utf8')) as PackageManifest;
}

function adoptManifestIdentity(
  candidate: PackageCandidate,
  manifest: PackageManifest
): PackageCandidate {
  return {
    ...candidate,
    name: manifest.name ?? candidate.name,
    version: manifest.version ?? candidate.version
  };
}

async function analyzeLocalDirectory(
  candidate: PackageCandidate,
  cwd: string
): Promise<LocalSourceAnalysis> {
  const resolvedPath = resolvedLocalPath(
    cwd,
    candidate.spec ?? candidate.requested ?? candidate.name
  );
  const nextCandidate: PackageCandidate = {
    ...candidate,
    sourceType: 'local-directory',
    resolvedPath
  };

  try {
    const sourceStats = await stat(resolvedPath);
    if (!sourceStats.isDirectory()) {
      return {
        candidate: nextCandidate,
        signals: [localSourceUninspectable(nextCandidate, 'Not a directory')]
      };
    }

    const manifestPath = join(resolvedPath, 'package.json');
    const manifest = await readJsonManifest(manifestPath);
    const manifestCandidate = adoptManifestIdentity(nextCandidate, manifest);
    return {
      candidate: manifestCandidate,
      signals: [...lifecycleSignals(manifest, manifest), ...manifestBehaviorSignals(manifest)]
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return {
      candidate: nextCandidate,
      signals: [
        code === 'ENOENT' && (error as Error).message.includes('package.json')
          ? localSourceManifestMissing(nextCandidate)
          : localSourceUninspectable(nextCandidate, error)
      ]
    };
  }
}

async function extractManifestFromTarball(path: string): Promise<PackageManifest | undefined> {
  const destination = await mkdtemp(join(tmpdir(), 'npm-gate-manifest-'));
  const packageDir = join(destination, 'package');
  let sawManifest = false;

  try {
    await mkdir(packageDir, { recursive: true });
    await tar.x({
      file: path,
      cwd: destination,
      filter(entryPath) {
        assertSafeTarPath(entryPath);
        const normalized = normalizeTarPath(entryPath);
        const isManifest = normalized === 'package/package.json';
        if (isManifest) sawManifest = true;
        return isManifest;
      },
      onentry(entry) {
        assertSafeTarPath(entry.path);
      }
    });

    if (!sawManifest) return undefined;
    return await readJsonManifest(join(packageDir, 'package.json'));
  } finally {
    await rm(destination, { recursive: true, force: true });
  }
}

async function analyzeLocalTarball(
  candidate: PackageCandidate,
  cwd: string
): Promise<LocalSourceAnalysis> {
  const resolvedPath = resolvedLocalPath(
    cwd,
    candidate.spec ?? candidate.requested ?? candidate.name
  );
  const nextCandidate: PackageCandidate = {
    ...candidate,
    sourceType: 'local-tarball',
    resolvedPath
  };

  try {
    const sourceStats = await stat(resolvedPath);
    if (!sourceStats.isFile()) {
      return {
        candidate: nextCandidate,
        signals: [localSourceUninspectable(nextCandidate, 'Not a file')]
      };
    }

    const inspection = await inspectTarballFile(resolvedPath);
    const manifest = await extractManifestFromTarball(resolvedPath);
    if (!manifest) {
      return {
        candidate: nextCandidate,
        signals: [...inspection.signals, localSourceManifestMissing(nextCandidate)]
      };
    }

    const manifestCandidate = adoptManifestIdentity(nextCandidate, manifest);
    return {
      candidate: manifestCandidate,
      signals: [
        ...inspection.signals,
        ...lifecycleSignals(manifest, manifest),
        ...manifestBehaviorSignals(manifest)
      ]
    };
  } catch (error) {
    const invalidManifest =
      error instanceof SyntaxError ||
      (error instanceof Error && error.message.includes('manifest read limit'));
    return {
      candidate: nextCandidate,
      signals: [
        invalidManifest
          ? localTarballManifestInvalid(nextCandidate, error)
          : localSourceUninspectable(nextCandidate, error)
      ]
    };
  }
}

function isDefaultSupportedRemoteTarballUrl(tarballUrl: string): boolean {
  try {
    const url = new URL(tarballUrl);
    return url.protocol === 'https:' && url.hostname === 'registry.npmjs.org';
  } catch {
    return false;
  }
}

async function analyzeRemoteTarball(
  candidate: PackageCandidate,
  registry: RegistryClient
): Promise<LocalSourceAnalysis> {
  const tarballUrl = candidate.spec ?? candidate.requested ?? candidate.name;
  const nextCandidate: PackageCandidate = {
    ...candidate,
    sourceType: 'remote-tarball'
  };

  const supported =
    registry.isSupportedTarballUrl?.(tarballUrl) ?? isDefaultSupportedRemoteTarballUrl(tarballUrl);
  if (!supported || !registry.fetchTarball) {
    return { candidate: nextCandidate, signals: [unsupportedRemoteTarball(nextCandidate)] };
  }

  const destination = await mkdtemp(join(tmpdir(), 'npm-gate-remote-tarball-'));
  const tarballPath = join(destination, 'package.tgz');
  try {
    const buffer = await registry.fetchTarball(tarballUrl);
    await writeFile(tarballPath, buffer);

    const inspection = await inspectTarballFile(tarballPath);
    const manifest = await extractManifestFromTarball(tarballPath);
    if (!manifest) {
      return {
        candidate: nextCandidate,
        signals: [...inspection.signals, remoteTarballManifestMissing(nextCandidate)]
      };
    }

    const manifestCandidate = adoptManifestIdentity(nextCandidate, manifest);
    return {
      candidate: manifestCandidate,
      signals: [
        ...inspection.signals,
        ...lifecycleSignals(manifest, manifest),
        ...manifestBehaviorSignals(manifest)
      ]
    };
  } catch (error) {
    const invalidManifest =
      error instanceof SyntaxError ||
      (error instanceof Error && error.message.includes('manifest read limit'));
    return {
      candidate: nextCandidate,
      signals: [
        invalidManifest
          ? remoteTarballManifestInvalid(nextCandidate, error)
          : remoteTarballUninspectable(nextCandidate, error)
      ]
    };
  } finally {
    await rm(destination, { recursive: true, force: true });
  }
}

export async function analyzeLocalSourceCandidate(
  candidate: PackageCandidate,
  cwd: string,
  registry?: RegistryClient
): Promise<LocalSourceAnalysis | undefined> {
  if (candidate.sourceType === 'remote-tarball-unsupported') {
    return { candidate, signals: [unsupportedRemoteTarball(candidate)] };
  }
  if (candidate.sourceType === 'remote-tarball') {
    if (!registry) return { candidate, signals: [unsupportedRemoteTarball(candidate)] };
    return analyzeRemoteTarball(candidate, registry);
  }
  if (candidate.sourceType === 'local-directory') {
    return analyzeLocalDirectory(candidate, cwd);
  }
  if (candidate.sourceType === 'local-tarball') {
    return analyzeLocalTarball(candidate, cwd);
  }
  return undefined;
}
