import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { RiskSignal } from '../core/types.js';
import { pathExists } from '../utils/fs.js';

export interface LockfileSecurityOptions {
  approvedRegistryHosts: string[];
  previousPackageLockPath?: string;
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

function lockEntries(
  lock: PackageLock
): Array<{ key: string; name: string; entry: PackageLockEntry }> {
  const entries: Array<{ key: string; name: string; entry: PackageLockEntry }> = [];
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!key.startsWith('node_modules/')) continue;
    const name = packageNameFromNodeModulesPath(key);
    if (!name) continue;
    entries.push({ key, name, entry });
  }
  for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
    entries.push({ key: `dependencies.${name}`, name, entry });
  }
  return entries;
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
  const path = join(cwd, 'package-lock.json');
  if (!(await pathExists(path))) return [];
  const approvedHosts = new Set(options.approvedRegistryHosts);
  const lock = await readPackageLock(path);
  const signals: RiskSignal[] = [];

  for (const { key, name, entry } of lockEntries(lock)) {
    if (!entry.resolved) continue;
    const host = resolvedHost(entry.resolved);
    if (host && !approvedHosts.has(host)) {
      signals.push(
        signal(
          'unapproved-resolved-host',
          'Lockfile resolves package tarball from an unapproved host',
          {
            file: 'package-lock.json',
            key,
            package: name,
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
    const previousByKey = new Map(lockEntries(previous).map((entry) => [entry.key, entry.entry]));
    for (const { key, name, entry } of lockEntries(lock)) {
      const old = previousByKey.get(key);
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
              file: 'package-lock.json',
              key,
              package: name,
              version: entry.version,
              previousIntegrity: old.integrity,
              currentIntegrity: entry.integrity
            }
          )
        );
      }
    }
  }

  return signals;
}
