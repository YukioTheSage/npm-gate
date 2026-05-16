import { createHash } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as tar from 'tar';
import type { PackageManifest, RegistryClient, RiskSignal, TarballEntry } from '../core/types.js';
import { sha256Buffer, sha256File } from '../utils/hashing.js';
import { analyzeTarballEntries, assertSafeTarPath } from '../analyzers/tarball-static-analyzer.js';

const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_ENTRY_SAMPLE_BYTES = 16 * 1024;
const DEFAULT_MAX_FULL_TEXT_ENTRY_BYTES = 1024 * 1024;
const sampleExtensions = new Set([
  '.cjs',
  '.cmd',
  '.js',
  '.json',
  '.mjs',
  '.ps1',
  '.sh',
  '.ts'
]);

export interface TarballInspection {
  sha256: string;
  entries: TarballEntry[];
  signals: RiskSignal[];
}

export interface TarballInspectionOptions {
  fullTextScanning?: boolean;
  maxFullTextEntryBytes?: number;
}

export interface RegistryPackageTarballInspection extends TarballInspection {
  manifest?: PackageManifest;
}

export async function inspectTarballBuffer(
  buffer: Buffer,
  options: TarballInspectionOptions = {}
): Promise<TarballInspection> {
  const dir = await mkdtemp(join(tmpdir(), 'npm-gate-tarball-'));
  const path = join(dir, 'package.tgz');
  try {
    await writeFile(path, buffer);
    return inspectTarballFile(path, sha256Buffer(buffer), options);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export async function inspectTarballFile(
  path: string,
  knownHash?: string,
  options: TarballInspectionOptions = {}
): Promise<TarballInspection> {
  const entries: TarballEntry[] = [];
  const maxFullTextEntryBytes =
    options.maxFullTextEntryBytes ?? DEFAULT_MAX_FULL_TEXT_ENTRY_BYTES;
  await tar.t({
    file: path,
    onentry(entry) {
      assertSafeTarPath(entry.path);
      const size = entry.size ?? 0;
      const tarballEntry: TarballEntry = { path: entry.path, size };
      entries.push(tarballEntry);

      if (!shouldSampleEntry(entry.path, size)) return;
      const chunks: Buffer[] = [];
      const fullTextChunks: Buffer[] = [];
      let sampledBytes = 0;
      const collectFullText = Boolean(options.fullTextScanning && size <= maxFullTextEntryBytes);
      entry.on('data', (chunk: Buffer) => {
        if (collectFullText) {
          fullTextChunks.push(chunk);
        }
        if (sampledBytes >= MAX_ENTRY_SAMPLE_BYTES) return;
        const remaining = MAX_ENTRY_SAMPLE_BYTES - sampledBytes;
        const next = chunk.subarray(0, remaining);
        sampledBytes += next.byteLength;
        chunks.push(next);
      });
      entry.on('end', () => {
        tarballEntry.sample = Buffer.concat(chunks).toString('utf8');
        if (collectFullText) {
          tarballEntry.fullText = Buffer.concat(fullTextChunks).toString('utf8');
        }
      });
    }
  });
  const analyzed = analyzeTarballEntries(entries);
  return {
    sha256: knownHash ?? (await sha256File(path)),
    entries,
    signals: [
      ...analyzed.signals,
      {
        id: 'tarball-hash',
        score: 0,
        severity: 'info',
        message: 'Tarball SHA-256 recorded',
        evidence: [
          {
            type: 'sha256',
            message: 'Package tarball hash',
            value: knownHash ?? (await sha256File(path))
          }
        ],
        remediation: [],
        canOverride: true
      }
    ]
  };
}

function shouldSampleEntry(path: string, size: number): boolean {
  if (size <= 0) return false;
  const normalized = path.toLowerCase();
  const dot = normalized.lastIndexOf('.');
  const extension = dot === -1 ? '' : normalized.slice(dot);
  return sampleExtensions.has(extension);
}

export async function extractTarballSafely(path: string, destination: string): Promise<void> {
  await tar.x({
    file: path,
    cwd: destination,
    filter(entryPath) {
      assertSafeTarPath(entryPath);
      return true;
    },
    onentry(entry) {
      assertSafeTarPath(entry.path);
    }
  });
}

async function extractManifestFromTarballFile(path: string): Promise<PackageManifest | undefined> {
  const destination = await mkdtemp(join(tmpdir(), 'npm-gate-registry-manifest-'));
  const packageDir = join(destination, 'package');
  let sawManifest = false;

  try {
    await mkdir(packageDir, { recursive: true });
    await tar.x({
      file: path,
      cwd: destination,
      filter(entryPath) {
        assertSafeTarPath(entryPath);
        const normalized = entryPath.replace(/\\/g, '/').replace(/\/\.\//g, '/');
        const isManifest = normalized === 'package/package.json';
        if (isManifest) sawManifest = true;
        return isManifest;
      },
      onentry(entry) {
        assertSafeTarPath(entry.path);
        if ((entry.size ?? 0) > MAX_MANIFEST_BYTES) {
          throw new Error(`package.json exceeds ${MAX_MANIFEST_BYTES} byte manifest read limit`);
        }
      }
    });

    if (!sawManifest) return undefined;
    const manifestPath = join(packageDir, 'package.json');
    const manifest = await readFile(manifestPath, 'utf8');
    if (Buffer.byteLength(manifest, 'utf8') > MAX_MANIFEST_BYTES) {
      throw new Error(`package.json exceeds ${MAX_MANIFEST_BYTES} byte manifest read limit`);
    }
    return JSON.parse(manifest) as PackageManifest;
  } finally {
    await rm(destination, { recursive: true, force: true });
  }
}

function registryTarballIntegrityMismatch(
  expectedIntegrity: string,
  actualAlgorithms: string[]
): RiskSignal {
  return {
    id: 'registry-tarball-integrity-mismatch',
    score: 70,
    severity: 'high',
    message: 'Registry tarball integrity does not match metadata',
    evidence: [
      {
        type: 'integrity',
        message: 'Expected package dist.integrity did not match fetched tarball bytes',
        value: { expectedIntegrity, actualAlgorithms }
      }
    ],
    remediation: [
      'Do not install this package version.',
      'Refresh registry metadata and lockfiles from a trusted registry.'
    ],
    canOverride: false
  };
}

function verifySubresourceIntegrity(
  buffer: Buffer,
  expectedIntegrity: string
): { matches: boolean; algorithms: string[] } {
  const supportedAlgorithms = new Set(['sha256', 'sha384', 'sha512']);
  const entries = expectedIntegrity
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  const algorithms: string[] = [];

  for (const entry of entries) {
    const separator = entry.indexOf('-');
    if (separator <= 0) continue;
    const algorithm = entry.slice(0, separator);
    const expected = entry.slice(separator + 1).split('?')[0];
    if (!supportedAlgorithms.has(algorithm) || !expected) continue;
    algorithms.push(algorithm);
    const actual = createHash(algorithm).update(buffer).digest('base64');
    if (actual === expected) return { matches: true, algorithms };
  }

  return { matches: false, algorithms };
}

export async function inspectRegistryTarball(
  client: RegistryClient,
  tarballUrl: string,
  expectedIntegrity?: string,
  options: TarballInspectionOptions = {}
): Promise<TarballInspection | undefined> {
  if (!client.fetchTarball) return undefined;
  const buffer = await client.fetchTarball(tarballUrl);
  const inspection = await inspectTarballBuffer(buffer, options);
  if (expectedIntegrity) {
    const integrity = verifySubresourceIntegrity(buffer, expectedIntegrity);
    if (!integrity.matches) {
      inspection.signals.push(
        registryTarballIntegrityMismatch(expectedIntegrity, integrity.algorithms)
      );
    }
  }
  return inspection;
}

export async function inspectRegistryPackageTarball(
  client: RegistryClient,
  tarballUrl: string,
  expectedIntegrity?: string,
  options: TarballInspectionOptions = {}
): Promise<RegistryPackageTarballInspection | undefined> {
  if (!client.fetchTarball) return undefined;
  const buffer = await client.fetchTarball(tarballUrl);
  const dir = await mkdtemp(join(tmpdir(), 'npm-gate-registry-package-'));
  const path = join(dir, 'package.tgz');
  try {
    await writeFile(path, buffer);
    const inspection = await inspectTarballFile(path, sha256Buffer(buffer), options);
    if (expectedIntegrity) {
      const integrity = verifySubresourceIntegrity(buffer, expectedIntegrity);
      if (!integrity.matches) {
        inspection.signals.push(
          registryTarballIntegrityMismatch(expectedIntegrity, integrity.algorithms)
        );
      }
    }
    return {
      ...inspection,
      manifest: await extractManifestFromTarballFile(path)
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
