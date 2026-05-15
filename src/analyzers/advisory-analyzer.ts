import { readFile } from 'node:fs/promises';
import semver from 'semver';
import { z } from 'zod';
import type { AdvisoryInput, RiskSignal } from '../core/types.js';

const advisoryRecordSchema = z.object({
  name: z.string(),
  versions: z.array(z.string()),
  type: z.enum(['malicious', 'vulnerability']).default('vulnerability'),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  summary: z.string()
});

const advisoryFeedSchema = z.object({
  packages: z.array(advisoryRecordSchema).default([])
});

export type AdvisoryRecord = AdvisoryInput;
export type AdvisoryFeed = z.infer<typeof advisoryFeedSchema>;

export async function loadLocalAdvisoryFeed(path: string): Promise<AdvisoryFeed> {
  return advisoryFeedSchema.parse(JSON.parse(await readFile(path, 'utf8')));
}

function versionMatches(version: string, pattern: string): boolean {
  return version === pattern || semver.satisfies(version, pattern, { includePrerelease: true });
}

export function matchLocalAdvisories(
  feed: AdvisoryFeed,
  name: string,
  version: string | undefined
): AdvisoryRecord[] {
  return feed.packages.filter(
    (record) =>
      record.name === name &&
      (!version || record.versions.some((pattern) => versionMatches(version, pattern)))
  );
}

export function advisorySignals(records: AdvisoryRecord[]): RiskSignal[] {
  return records.map((record) => ({
    id: record.type === 'malicious' ? 'known-malicious-advisory' : 'known-vulnerability-advisory',
    score: record.type === 'malicious' ? 80 : record.severity === 'critical' ? 60 : 35,
    severity: record.severity,
    message: `${record.type} advisory matched: ${record.summary}`,
    evidence: [{ type: 'advisory', message: record.summary, value: record }],
    remediation: [
      'Do not install the affected version. Pin or upgrade to a reviewed safe version.'
    ],
    canOverride: record.type !== 'malicious'
  }));
}

export function parseNpmAuditJson(raw: string): AdvisoryRecord[] {
  if (!raw.trim()) return [];
  const audit = JSON.parse(raw) as {
    vulnerabilities?: Record<
      string,
      {
        name?: string;
        severity?: AdvisoryRecord['severity'];
        title?: string;
        via?: Array<
          string | { title?: string; severity?: AdvisoryRecord['severity']; range?: string }
        >;
        range?: string;
      }
    >;
  };

  return Object.entries(audit.vulnerabilities ?? {}).map(([name, vulnerability]) => ({
    name: vulnerability.name ?? name,
    versions: [
      vulnerability.range ??
        vulnerability.via?.find(
          (item): item is { range: string } => typeof item === 'object' && Boolean(item.range)
        )?.range ??
        '*'
    ],
    type: 'vulnerability',
    severity: vulnerability.severity ?? 'medium',
    summary:
      vulnerability.title ??
      vulnerability.via?.find(
        (item): item is { title: string } => typeof item === 'object' && Boolean(item.title)
      )?.title ??
      'npm audit advisory'
  }));
}
