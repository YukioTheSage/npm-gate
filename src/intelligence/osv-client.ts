import type { AdvisoryInput, IntelligenceClient, IntelligencePackageQuery } from '../core/types.js';

interface OsvQueryResult {
  vulns?: Array<{
    id: string;
    summary?: string;
    details?: string;
    database_specific?: { severity?: string };
  }>;
}

function normalizeSeverity(value: unknown): AdvisoryInput['severity'] {
  const severity = typeof value === 'string' ? value.toLowerCase() : '';
  if (
    severity === 'critical' ||
    severity === 'high' ||
    severity === 'medium' ||
    severity === 'low'
  ) {
    return severity;
  }
  return 'medium';
}

export class OsvIntelligenceClient implements IntelligenceClient {
  constructor(private readonly endpoint = 'https://api.osv.dev/v1/querybatch') {}

  async queryVulnerabilities(packages: IntelligencePackageQuery[]): Promise<AdvisoryInput[]> {
    if (packages.length === 0) return [];
    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: packages.map((dependency) => ({
          version: dependency.version,
          package: { ecosystem: 'npm', name: dependency.name }
        }))
      })
    });
    if (!response.ok) {
      throw new Error(`OSV query failed with HTTP ${response.status}`);
    }

    const body = (await response.json()) as { results?: OsvQueryResult[] };
    return (body.results ?? []).flatMap((result, index) =>
      (result.vulns ?? []).map((vuln) => ({
        name: packages[index]?.name ?? 'unknown',
        versions: packages[index]?.version ? [packages[index]!.version!] : ['*'],
        type: 'vulnerability' as const,
        severity: normalizeSeverity(vuln.database_specific?.severity),
        summary: vuln.summary ?? vuln.details ?? vuln.id
      }))
    );
  }
}
