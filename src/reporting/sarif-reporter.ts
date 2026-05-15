import type { ScanReport } from '../core/types.js';

function locationForFinding(finding: ScanReport['findings'][number]): object[] | undefined {
  const fileEvidence = finding.evidence.find(
    (evidence) =>
      evidence.type === 'file' &&
      evidence.value &&
      typeof evidence.value === 'object' &&
      'file' in evidence.value
  );
  if (!fileEvidence?.value || typeof fileEvidence.value !== 'object') return undefined;
  const value = fileEvidence.value as { file?: string; line?: number };
  if (!value.file) return undefined;
  return [
    {
      physicalLocation: {
        artifactLocation: { uri: value.file },
        region: { startLine: value.line ?? 1 }
      }
    }
  ];
}

export function createSarifReport(report: ScanReport): object {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'npm-gate',
            version: report.toolVersion,
            rules: report.findings.map((finding) => ({
              id: finding.id,
              shortDescription: { text: `${finding.package} ${finding.decision}` },
              fullDescription: { text: finding.reasons.join('\n') },
              defaultConfiguration: {
                level:
                  finding.decision === 'block'
                    ? 'error'
                    : finding.decision === 'warn'
                      ? 'warning'
                      : 'note'
              }
            }))
          }
        },
        results: report.findings
          .filter((finding) => finding.decision !== 'allow')
          .map((finding) => ({
            ruleId: finding.id,
            level: finding.decision === 'block' ? 'error' : 'warning',
            message: { text: finding.reasons.join('\n') },
            locations: locationForFinding(finding),
            properties: {
              package: finding.package,
              version: finding.version,
              score: finding.score,
              suppressed: Boolean(finding.suppressed)
            }
          }))
      }
    ]
  };
}
