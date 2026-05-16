import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { RiskSignal } from '../core/types.js';
import { pathExists } from '../utils/fs.js';

export interface LockfileSecurityOptions {
  approvedRegistryHosts: string[];
  previousPackageLockPath?: string;
  previousPnpmLockPath?: string;
  previousYarnLockPath?: string;
}

interface PackageLockEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
}

interface PackageLock {
  packages?: Record<string, PackageLockEntry>;
  dependencies?: Record<string, PackageLockEntry>;
}

interface LockSecurityEntry {
  file: string;
  key: string;
  name: string;
  version?: string;
  resolved?: string;
  integrity?: string;
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

async function readPackageLock(path: string): Promise<PackageLock> {
  return JSON.parse(await readFile(path, 'utf8')) as PackageLock;
}

function resolvedHost(resolved: string): string | undefined {
  try {
    return new URL(resolved).hostname;
  } catch {
    return undefined;
  }
}

function packageLockEntries(lock: PackageLock, file: string): LockSecurityEntry[] {
  const entries: LockSecurityEntry[] = [];
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith('node_modules/')) continue;
    const name = packageNameFromNodeModulesPath(key);
    if (!name) continue;
    entries.push({
      file,
      key,
      name,
      version: entry.version,
      resolved: entry.resolved,
      integrity: entry.integrity
    });
  }
  for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
    entries.push({
      file,
      key: `dependencies.${name}`,
      name,
      version: entry.version,
      resolved: entry.resolved,
      integrity: entry.integrity
    });
  }
  return entries;
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

async function pnpmLockEntries(path: string): Promise<LockSecurityEntry[]> {
  const lock = parseYaml(await readFile(path, 'utf8')) as
    | { packages?: Record<string, { resolution?: { tarball?: string; integrity?: string } }> }
    | null;
  return Object.entries(lock?.packages ?? {}).flatMap(([key, entry]) => {
    const parsed = parsePnpmPackageKey(key);
    if (!parsed) return [];
    return [
      {
        file: 'pnpm-lock.yaml',
        key,
        name: parsed.name,
        version: parsed.version,
        resolved: entry.resolution?.tarball,
        integrity: entry.resolution?.integrity
      }
    ];
  });
}

function yarnNamesFromHeader(header: string): string[] {
  return header.split(/,\s*/).map((part) => {
    const clean = part.trim().replace(/^"|"$/g, '');
    const at = clean.startsWith('@')
      ? clean.indexOf('@', clean.indexOf('/'))
      : clean.lastIndexOf('@');
    return at > 0 ? clean.slice(0, at) : clean;
  });
}

async function yarnLockEntries(path: string): Promise<LockSecurityEntry[]> {
  const entries: LockSecurityEntry[] = [];
  const content = await readFile(path, 'utf8');
  let names: string[] = [];
  let version: string | undefined;
  let resolved: string | undefined;
  let integrity: string | undefined;
  let key = '';

  function flush(): void {
    for (const name of names) {
      entries.push({ file: 'yarn.lock', key, name, version, resolved, integrity });
    }
  }

  for (const line of content.split(/\r?\n/)) {
    const header = line.match(/^("?)([^"\s][^:]+)\1:\s*$/);
    if (header) {
      flush();
      key = header[2]!;
      names = yarnNamesFromHeader(key);
      version = undefined;
      resolved = undefined;
      integrity = undefined;
      continue;
    }
    version = line.match(/^\s+version\s+"([^"]+)"/)?.[1] ?? version;
    resolved = line.match(/^\s+resolved\s+"([^"]+)"/)?.[1] ?? resolved;
    integrity = line.match(/^\s+integrity\s+(.+)$/)?.[1]?.trim() ?? integrity;
  }
  flush();
  return entries.filter((entry) => entry.version || entry.resolved || entry.integrity);
}

async function currentLockEntries(cwd: string): Promise<LockSecurityEntry[]> {
  const entries: LockSecurityEntry[] = [];
  for (const file of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const path = join(cwd, file);
    if (await pathExists(path)) {
      entries.push(...packageLockEntries(await readPackageLock(path), file));
    }
  }
  const pnpmPath = join(cwd, 'pnpm-lock.yaml');
  if (await pathExists(pnpmPath)) {
    entries.push(...(await pnpmLockEntries(pnpmPath)));
  }
  const yarnPath = join(cwd, 'yarn.lock');
  if (await pathExists(yarnPath)) {
    entries.push(...(await yarnLockEntries(yarnPath)));
  }
  return entries;
}

function integrityChangeSignals(
  currentEntries: LockSecurityEntry[],
  previousEntries: LockSecurityEntry[],
  file: string
): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const previousByKey = new Map(previousEntries.map((entry) => [entry.key, entry]));
  for (const entry of currentEntries.filter((current) => current.file === file)) {
    const old = previousByKey.get(entry.key);
    if (
      old?.version &&
      entry.version === old.version &&
      old.integrity &&
      entry.integrity &&
      old.integrity !== entry.integrity
    ) {
      signals.push(
        signal(
          'lockfile-integrity-changed',
          'Lockfile integrity changed without a package version change',
          {
            file,
            key: entry.key,
            package: entry.name,
            version: entry.version,
            previousIntegrity: old.integrity,
            currentIntegrity: entry.integrity
          }
        )
      );
    }
  }
  return signals;
}

function signal(
  id: string,
  message: string,
  value: unknown,
  score = 70,
  severity: RiskSignal['severity'] = 'high'
): RiskSignal {
  return {
    id,
    score,
    severity,
    message,
    evidence: [{ type: 'lockfile', message, value }],
    remediation: [
      'Regenerate the lockfile from a trusted registry.',
      'Require review before accepting this dependency change.'
    ],
    canOverride: false
  };
}

export async function analyzeLockfileSecurity(
  cwd: string,
  options: LockfileSecurityOptions
): Promise<RiskSignal[]> {
  const approvedHosts = new Set(options.approvedRegistryHosts);
  const entries = await currentLockEntries(cwd);
  const signals: RiskSignal[] = [];

  for (const entry of entries) {
    if (!entry.resolved) continue;
    const host = resolvedHost(entry.resolved);
    if (host && !approvedHosts.has(host)) {
      signals.push(
        signal(
          'unapproved-resolved-host',
          'Lockfile resolves package tarball from an unapproved host',
          {
            file: entry.file,
            key: entry.key,
            package: entry.name,
            version: entry.version,
            resolved: entry.resolved,
            host,
            approvedHosts: [...approvedHosts]
          }
        )
      );
    }
  }

  if (options.previousPackageLockPath && (await pathExists(options.previousPackageLockPath))) {
    const previous = await readPackageLock(options.previousPackageLockPath);
    signals.push(
      ...integrityChangeSignals(
        entries,
        packageLockEntries(previous, 'package-lock.json'),
        'package-lock.json'
      )
    );
  }

  if (options.previousPnpmLockPath && (await pathExists(options.previousPnpmLockPath))) {
    signals.push(
      ...integrityChangeSignals(
        entries,
        await pnpmLockEntries(options.previousPnpmLockPath),
        'pnpm-lock.yaml'
      )
    );
  }

  if (options.previousYarnLockPath && (await pathExists(options.previousYarnLockPath))) {
    signals.push(
      ...integrityChangeSignals(
        entries,
        await yarnLockEntries(options.previousYarnLockPath),
        'yarn.lock'
      )
    );
  }

  return signals;
}
