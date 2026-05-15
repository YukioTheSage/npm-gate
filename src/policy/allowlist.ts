import { join } from 'node:path';
import semver from 'semver';
import { ensureDir, pathExists, readJsonFile, writeJsonFile } from '../utils/fs.js';
import { isExpired } from '../utils/time.js';

export interface AllowlistEntry {
  package: string;
  version: string;
  reason: string;
  addedBy: string;
  addedAt: string;
  expiresAt?: string;
  ticket?: string;
}

export class Allowlist {
  constructor(public readonly entries: AllowlistEntry[]) {}

  match(
    packageName: string,
    version: string | undefined,
    now = new Date()
  ): AllowlistEntry | undefined {
    return this.entries.find((entry) => {
      if (entry.package !== packageName || isExpired(entry.expiresAt, now)) return false;
      if (!version) return true;
      return (
        entry.version === version ||
        semver.satisfies(version, entry.version, { includePrerelease: true })
      );
    });
  }
}

function allowlistPath(cwd: string): string {
  return join(cwd, '.npm-gate', 'allowlist.json');
}

export async function loadAllowlist(cwd: string): Promise<Allowlist> {
  const path = allowlistPath(cwd);
  if (!(await pathExists(path))) return new Allowlist([]);
  const raw = await readJsonFile<{ allowlist?: AllowlistEntry[]; entries?: AllowlistEntry[] }>(
    path
  );
  return new Allowlist(raw.allowlist ?? raw.entries ?? []);
}

export async function writeAllowlistEntry(cwd: string, entry: AllowlistEntry): Promise<void> {
  const path = allowlistPath(cwd);
  await ensureDir(join(cwd, '.npm-gate'));
  const current = await loadAllowlist(cwd);
  await writeJsonFile(path, { allowlist: [...current.entries, entry] });
}
