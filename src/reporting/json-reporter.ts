import type { ScanReport, ScanReportInput } from '../core/types.js';

export function createJsonReport(input: ScanReportInput): ScanReport {
  return {
    ...input,
    summary: {
      allow: input.findings.filter((finding) => finding.decision === 'allow' && !finding.suppressed)
        .length,
      warn: input.findings.filter((finding) => finding.decision === 'warn' && !finding.suppressed)
        .length,
      block: input.findings.filter((finding) => finding.decision === 'block' && !finding.suppressed)
        .length,
      suppressed: input.findings.filter((finding) => finding.suppressed).length
    }
  };
}

export function stringifyJsonReport(input: ScanReportInput): string {
  return `${JSON.stringify(createJsonReport(input), null, 2)}\n`;
}
