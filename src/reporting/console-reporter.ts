import pc from 'picocolors';
import type { PackageFinding, ScanReport } from '../core/types.js';

function label(finding: PackageFinding): string {
  if (finding.suppressed) return pc.gray('SUPPRESSED');
  if (finding.decision === 'block') return pc.red('BLOCKED');
  if (finding.decision === 'manual_review') return pc.magenta('REVIEW');
  if (finding.decision === 'warn') return pc.yellow('WARN');
  return pc.green('ALLOW');
}

export function renderConsoleReport(report: ScanReport): string {
  const manualReview = report.findings.filter(
    (finding) => finding.decision === 'manual_review' && !finding.suppressed
  ).length;
  const lines = [
    `npm-gate ${report.mode} report${report.policyMode ? ` (${report.policyMode} policy)` : ''}`,
    `Summary: ${report.summary.allow} allow, ${report.summary.warn} warn, ${manualReview} manual review, ${report.summary.block} block, ${report.summary.suppressed} suppressed`
  ];

  for (const finding of report.findings) {
    lines.push('');
    lines.push(
      `${label(finding)}: ${finding.package}${finding.version ? `@${finding.version}` : ''}`
    );
    lines.push(`Risk score: ${finding.score} ${finding.severity}`);
    if (finding.riskCategory) lines.push(`Risk category: ${finding.riskCategory}`);
    if (finding.dependencyPath?.length) {
      lines.push(`Dependency path: ${finding.dependencyPath.join(' > ')}`);
    }
    if (finding.matchedSignals?.length) {
      lines.push(`Matched signals: ${finding.matchedSignals.join(', ')}`);
    }
    if (finding.evidenceSummary) lines.push(`Evidence: ${finding.evidenceSummary}`);
    if (finding.killChain) lines.push(`Kill chain: ${finding.killChain}`);
    if (finding.allowlist) {
      if (finding.allowlist.used) {
        lines.push(
          `Allowlist: ${finding.allowlist.scope ?? 'entry'}${finding.allowlist.reason ? ` (${finding.allowlist.reason})` : ''}`
        );
      } else if (finding.allowlist.failures?.length) {
        lines.push(`Allowlist rejected: ${finding.allowlist.failures.join('; ')}`);
      }
    }
    if (finding.suppressed) lines.push(`Suppressed: ${finding.suppressed.reason}`);
    lines.push('Reasons:');
    for (const reason of finding.reasons) lines.push(`- ${reason}`);
    lines.push('Recommended actions:');
    for (const action of finding.remediation) lines.push(`- ${action}`);
  }

  return `${lines.join('\n')}\n`;
}
