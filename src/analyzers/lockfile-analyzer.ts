import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { parse as parseYaml } from 'yaml';
import type { PackageCandidate } from '../core/types.js';
import { pathExists } from '../utils/fs.js';

interface PackageLockEntry {
  name?: string;
  version?: string;
}

interface PackageLock {
  name?: string;
  version?: string;
  packages?: Record<string, PackageLockEntry>;
  dependencies?: Record<string, PackageLockEntry | string>;
}

function depCandidates(
  dependencies: Record<string, PackageLockEntry | string> | undefined,
  source: string
): PackageCandidate[] {
  return Object.entries(dependencies ?? {}).map(([name, value]) => ({
    name,
    version: typeof value === 'string' ? value : value.version,
    spec: typeof value === 'string' ? value : value.version,
    source
  }));
}

function packageNameFromNodeModulesPath(path: string): string | undefined {
  const parts = path.split(/[\\/]+/);
  const nodeModulesIndex = parts.lastIndexOf('node_modules');
  if (nodeModulesIndex === -1) return undefined;

  const first = parts[nodeModulesIndex + 1];
  if (!first) return undefined;
  if (first.startsWith('@')) {
    const second = parts[nodeModulesIndex + 2];
    return second ? `${first}/${second}` : undefined;
  }
  return first;
}

function packageSegmentsFromNodeModulesPath(path: string): string[] {
  const parts = path.split(/[\\/]+/);
  const packages: string[] = [];
  for (let index = 0; index < parts.length; index += 1) {
    if (parts[index] !== 'node_modules') continue;
    const first = parts[index + 1];
    if (!first) continue;
    if (first.startsWith('@')) {
      const second = parts[index + 2];
      if (second) packages.push(`${first}/${second}`);
      index += 2;
    } else {
      packages.push(first);
      index += 1;
    }
  }
  return packages;
}

function packageKeyFromSegments(segments: string[]): string {
  return segments.map((segment) => `node_modules/${segment}`).join('/');
}

function packageLabel(name: string, version?: string): string {
  return `${name}@${version ?? 'unknown'}`;
}

function rootDependencyPath(lock: PackageLock): string[] {
  const root = lock.packages?.[''];
  const name = root?.name ?? lock.name;
  const version = root?.version ?? lock.version;
  return name && version ? [packageLabel(name, version)] : [];
}

function dependencyPathForPackageKey(
  lock: PackageLock,
  key: string,
  entry: PackageLockEntry
): string[] | undefined {
  const segments = packageSegmentsFromNodeModulesPath(key);
  if (segments.length === 0) return undefined;
  const path = rootDependencyPath(lock);
  for (let index = 0; index < segments.length; index += 1) {
    const name = segments[index]!;
    const packageKey = packageKeyFromSegments(segments.slice(0, index + 1));
    const version =
      index === segments.length - 1 ? entry.version : lock.packages?.[packageKey]?.version;
    path.push(packageLabel(name, version));
  }
  return path;
}

function dependencyPathForTopLevelDependency(
  lock: PackageLock,
  name: string,
  entry: PackageLockEntry | string
): string[] | undefined {
  const path = rootDependencyPath(lock);
  if (path.length === 0) return undefined;
  path.push(packageLabel(name, typeof entry === 'string' ? entry : entry.version));
  return path;
}

function parsePnpmPackageKey(key: string): { name: string; version: string } | undefined {
  const normalized = key
    .trim()
    .replace(/^\/+/, '')
    .replace(/\([^)]*\)$/, '');
  const versionAt = normalized.lastIndexOf('@');
  if (versionAt <= 0) return undefined;

  const name = normalized.slice(0, versionAt);
  const version = normalized.slice(versionAt + 1);
  return name && version ? { name, version } : undefined;
}

export async function scanPackageLock(cwd: string): Promise<PackageCandidate[]> {
  const files = ['package-lock.json', 'npm-shrinkwrap.json'];
  const candidates: PackageCandidate[] = [];
  for (const file of files) {
    const path = join(cwd, file);
    if (!(await pathExists(path))) continue;
    const lock = JSON.parse(await readFile(path, 'utf8')) as PackageLock;
    candidates.push(
      ...depCandidates(lock.dependencies, file).map((candidate) => {
        const entry = lock.dependencies?.[candidate.name];
        return {
          ...candidate,
          dependencyPath: entry
            ? dependencyPathForTopLevelDependency(lock, candidate.name, entry)
            : undefined
        };
      })
    );
    if (lock.packages) {
      for (const [key, value] of Object.entries(lock.packages)) {
        if (!key.startsWith('node_modules/')) continue;
        const name = packageNameFromNodeModulesPath(key);
        if (!name) continue;
        candidates.push({
          name,
          version: value.version,
          spec: value.version,
          source: file,
          dependencyPath: dependencyPathForPackageKey(lock, key, value)
        });
      }
    }
  }
  return candidates;
}

export async function scanPnpmLock(cwd: string): Promise<PackageCandidate[]> {
  const path = join(cwd, 'pnpm-lock.yaml');
  if (!(await pathExists(path))) return [];
  const content = await readFile(path, 'utf8');
  const lock = parseYaml(content) as { packages?: Record<string, unknown> } | null;
  const candidates: PackageCandidate[] = [];
  for (const key of Object.keys(lock?.packages ?? {})) {
    const parsed = parsePnpmPackageKey(key);
    if (!parsed) continue;
    candidates.push({
      name: parsed.name,
      version: parsed.version,
      spec: parsed.version,
      source: 'pnpm-lock.yaml'
    });
  }
  return candidates;
}

export async function scanYarnLock(cwd: string): Promise<PackageCandidate[]> {
  const path = join(cwd, 'yarn.lock');
  if (!(await pathExists(path))) return [];
  const content = await readFile(path, 'utf8');
  const candidates: PackageCandidate[] = [];
  const currentNames: string[] = [];
  for (const line of content.split(/\r?\n/)) {
    const header = line.match(/^("?)([^"\s][^:]+)\1:\s*$/);
    if (header) {
      currentNames.length = 0;
      for (const part of header[2]!.split(/,\s*/)) {
        const clean = part.replace(/^"|"$/g, '');
        const at = clean.startsWith('@')
          ? clean.indexOf('@', clean.indexOf('/'))
          : clean.lastIndexOf('@');
        currentNames.push(at > 0 ? clean.slice(0, at) : clean);
      }
    }
    const version = line.match(/^\s+version\s+"([^"]+)"/);
    if (version) {
      candidates.push(
        ...currentNames.map((name) => ({
          name,
          version: version[1]!,
          spec: version[1]!,
          source: 'yarn.lock'
        }))
      );
    }
  }
  return candidates;
}

export async function scanLockfiles(cwd: string): Promise<PackageCandidate[]> {
  return [
    ...(await scanPackageLock(cwd)),
    ...(await scanPnpmLock(cwd)),
    ...(await scanYarnLock(cwd))
  ];
}
