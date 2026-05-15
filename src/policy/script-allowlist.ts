import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { LifecycleScript, RiskSignal } from '../core/types.js';
import { pathExists, readJsonFile } from '../utils/fs.js';
import { isExpired } from '../utils/time.js';

export interface ScriptAllowlistEntry {
  package: string;
  version: string;
  script: string;
  commandSha256: string;
  justification: string;
  integrity?: string;
  tarballSha256?: string;
  expiresAt?: string;
}

export interface ScriptAllowlistRequest {
  packageName: string;
  version?: string;
  script: LifecycleScript;
  integrity?: string;
  tarballSha256?: string;
  now?: Date;
}

export interface ScriptAllowlistFailure {
  entry?: ScriptAllowlistEntry;
  reason: string;
}

export interface ScriptAllowlistResult {
  allowed: boolean;
  entry?: ScriptAllowlistEntry;
  failures: ScriptAllowlistFailure[];
}

export function hashScriptCommand(command: string): string {
  return createHash('sha256').update(command).digest('hex');
}

function scriptAllowlistPath(cwd: string): string {
  return join(cwd, '.npm-gate', 'script-allowlist.json');
}

function reasonsForEntry(
  entry: ScriptAllowlistEntry,
  request: ScriptAllowlistRequest
): string[] {
  const reasons: string[] = [];
  if (entry.package !== request.packageName) reasons.push('package mismatch');
  if (entry.version.includes('*') || entry.version.includes('^') || entry.version.includes('~')) {
    reasons.push('version must be exact');
  }
  if (!request.version || entry.version !== request.version) reasons.push('version mismatch');
  if (entry.script !== request.script.name) reasons.push('script name mismatch');
  if (entry.commandSha256 !== hashScriptCommand(request.script.command)) {
    reasons.push('script command hash mismatch');
  }
  if (!entry.justification.trim()) reasons.push('missing justification');
  if (isExpired(entry.expiresAt, request.now ?? new Date())) reasons.push('entry expired');
  if (request.integrity && entry.integrity !== request.integrity) reasons.push('integrity mismatch');
  if (request.tarballSha256 && entry.tarballSha256 !== request.tarballSha256) {
    reasons.push('tarball hash mismatch');
  }
  return reasons;
}

export class ScriptAllowlist {
  constructor(public readonly entries: ScriptAllowlistEntry[]) {}

  authorize(request: ScriptAllowlistRequest): ScriptAllowlistResult {
    const failures: ScriptAllowlistFailure[] = [];
    for (const entry of this.entries) {
      const reasons = reasonsForEntry(entry, request);
      if (reasons.length === 0) return { allowed: true, entry, failures: [] };
      if (entry.package === request.packageName || entry.script === request.script.name) {
        failures.push(...reasons.map((reason) => ({ entry, reason })));
      }
    }
    return { allowed: false, failures };
  }
}

export async function loadScriptAllowlist(cwd: string): Promise<ScriptAllowlist> {
  const path = scriptAllowlistPath(cwd);
  if (!(await pathExists(path))) return new ScriptAllowlist([]);
  const raw = await readJsonFile<{
    scripts?: ScriptAllowlistEntry[];
    allowlist?: ScriptAllowlistEntry[];
    entries?: ScriptAllowlistEntry[];
  }>(path);
  return new ScriptAllowlist(raw.scripts ?? raw.allowlist ?? raw.entries ?? []);
}

function scriptFromSignal(signal: RiskSignal): LifecycleScript | undefined {
  const script = signal.evidence
    ?.map((evidence) => evidence.value)
    .find((value): value is LifecycleScript => {
      return (
        Boolean(value) &&
        typeof value === 'object' &&
        typeof (value as LifecycleScript).name === 'string' &&
        typeof (value as LifecycleScript).command === 'string'
      );
    });
  return script;
}

export function applyScriptAllowlist(input: {
  signals: RiskSignal[];
  allowlist: ScriptAllowlist;
  packageName: string;
  version?: string;
  integrity?: string;
  tarballSha256?: string;
  now?: Date;
}): { signals: RiskSignal[]; used: ScriptAllowlistEntry[]; failures: ScriptAllowlistFailure[] } {
  const used: ScriptAllowlistEntry[] = [];
  const failures: ScriptAllowlistFailure[] = [];
  const signals: RiskSignal[] = [];

  for (const signal of input.signals) {
    if (signal.riskCategory !== 'lifecycle_script_risk') {
      signals.push(signal);
      continue;
    }
    const script = scriptFromSignal(signal);
    if (!script) {
      signals.push(signal);
      continue;
    }
    const result = input.allowlist.authorize({
      packageName: input.packageName,
      version: input.version,
      script,
      integrity: input.integrity,
      tarballSha256: input.tarballSha256,
      now: input.now
    });
    failures.push(...result.failures);
    if (result.allowed && result.entry) {
      used.push(result.entry);
      continue;
    }
    signals.push(signal);
  }

  if (used.length > 0) {
    signals.push({
      id: 'script-allowlist-match',
      score: 0,
      severity: 'info',
      riskCategory: 'lifecycle_script_risk',
      message: 'Lifecycle script authorized by exact script hash allowlist',
      evidence: used.map((entry) => ({
        type: 'script-allowlist',
        message: `${entry.package}@${entry.version} ${entry.script} allowed`,
        value: {
          package: entry.package,
          version: entry.version,
          script: entry.script,
          justification: entry.justification,
          expiresAt: entry.expiresAt
        }
      })),
      remediation: [],
      canOverride: true
    });
  }

  if (failures.length > 0 && used.length === 0) {
    signals.push({
      id: 'script-allowlist-mismatch',
      score: 10,
      severity: 'low',
      riskCategory: 'lifecycle_script_risk',
      message: 'Lifecycle script allowlist entry did not match exactly',
      evidence: failures.map((failure) => ({
        type: 'script-allowlist',
        message: failure.reason,
        value: failure.entry
          ? {
              package: failure.entry.package,
              version: failure.entry.version,
              script: failure.entry.script,
              expiresAt: failure.entry.expiresAt
            }
          : undefined
      })),
      remediation: ['Create a narrow allowlist entry for the exact version, script hash, and integrity.'],
      canOverride: true
    });
  }

  return { signals, used, failures };
}
