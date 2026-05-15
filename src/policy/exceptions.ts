import { join } from 'node:path';
import type { PackageFinding } from '../core/types.js';
import { isExpired } from '../utils/time.js';
import { pathExists, readJsonFile } from '../utils/fs.js';

export interface ExceptionEntry {
  findingId: string;
  package: string;
  version?: string;
  reason: string;
  expiresAt?: string;
  createdAt: string;
}

export class ExceptionStore {
  constructor(public readonly entries: ExceptionEntry[]) {}

  match(finding: PackageFinding, now = new Date()): ExceptionEntry | undefined {
    return this.entries.find(
      (entry) =>
        entry.findingId === finding.id &&
        entry.package === finding.package &&
        (!entry.version || entry.version === finding.version) &&
        !isExpired(entry.expiresAt, now)
    );
  }
}

export async function loadExceptions(cwd: string): Promise<ExceptionStore> {
  const paths = [
    join(cwd, '.npm-gate', 'exceptions.json'),
    join(cwd, '.npm-gate-exceptions.json')
  ];
  for (const path of paths) {
    if (!(await pathExists(path))) continue;
    const raw = await readJsonFile<{ exceptions?: ExceptionEntry[]; entries?: ExceptionEntry[] }>(
      path
    );
    return new ExceptionStore(raw.exceptions ?? raw.entries ?? []);
  }
  return new ExceptionStore([]);
}

export function applyExceptions(
  store: ExceptionStore,
  findings: PackageFinding[],
  now = new Date()
): PackageFinding[] {
  return findings.map((finding) => {
    if (!finding.canOverride) return finding;
    const exception = store.match(finding, now);
    if (!exception) return finding;
    return {
      ...finding,
      suppressed: {
        reason: exception.reason,
        exceptionId: exception.findingId,
        expiresAt: exception.expiresAt
      }
    };
  });
}
