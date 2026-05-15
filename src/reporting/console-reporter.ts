import pc from 'picocolors';
import type { PackageFinding, ScanReport } from '../core/types.js';

function label(finding: PackageFinding): string {
  if (finding.suppressed) return pc.gray('SUPPRESSED');
  if (finding.decision === 'block') return pc.red('BLOCKED');
  if (finding.decision === 'warn') return pc.yellow('WARN');
  return pc.green('ALLOW');
}

export function renderConsoleReport(report: ScanReport): string {
  const lines = [
    `npm-gate ${report.mode} report`,
    `Summary: ${report.summary.allow} allow, ${report.summary.warn} warn, ${report.summary.block} block, ${report.summary.suppressed} suppressed`
  ];

  for (const finding of report.findings) {
    lines.push('');
    lines.push(
      `${label(finding)}: ${finding.package}${finding.version ? `@${finding.version}` : ''}`
    );
    lines.push(`Risk score: ${finding.score} ${finding.severity}`);
    if (finding.suppressed) lines.push(`Suppressed: ${finding.suppressed.reason}`);
    lines.push('Reasons:');
    for (const reason of finding.reasons) lines.push(`- ${reason}`);
    lines.push('Recommended actions:');
    for (const action of finding.remediation) lines.push(`- ${action}`);
  }

  return `${lines.join('\n')}\n`;
}
