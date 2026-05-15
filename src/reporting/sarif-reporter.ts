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
  const levelForDecision = (decision: ScanReport['findings'][number]['decision']) =>
    decision === 'block'
      ? 'error'
      : decision === 'warn' || decision === 'manual_review'
        ? 'warning'
        : 'note';

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
                level: levelForDecision(finding.decision)
              }
            }))
          }
        },
        results: report.findings
          .filter((finding) => finding.decision !== 'allow')
          .map((finding) => ({
            ruleId: finding.id,
            level: levelForDecision(finding.decision),
            message: { text: finding.reasons.join('\n') },
            locations: locationForFinding(finding),
            properties: {
              package: finding.package,
              version: finding.version,
              score: finding.score,
              decision: finding.decision,
              severity: finding.severity,
              riskCategory: finding.riskCategory,
              policyMode: finding.policyMode ?? report.policyMode,
              matchedSignals: finding.matchedSignals,
              evidenceSummary: finding.evidenceSummary,
              recommendedFix: finding.recommendedFix,
              dependencyPath: finding.dependencyPath,
              allowlist: finding.allowlist,
              killChain: finding.killChain,
              canOverride: finding.canOverride,
              suppressed: Boolean(finding.suppressed)
            }
          }))
      }
    ]
  };
}
