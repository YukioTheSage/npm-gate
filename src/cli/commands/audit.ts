import type { Command } from 'commander';
import { scanProject } from '../../core/engine.js';
import { exitCodeForFindings } from '../../core/decision.js';
import { renderConsoleReport } from '../../reporting/console-reporter.js';
import { runCommand } from '../../utils/exec.js';
import { parseNpmAuditJson } from '../../analyzers/advisory-analyzer.js';

export function registerAuditCommand(program: Command): void {
  program
    .command('audit')
    .description('Run local npm audit JSON when available, then run npm-gate scan')
    .option('--json', 'print JSON scan report')
    .option('--strict', 'fail on warnings and blocks')
    .option('--production', 'use production hardening profile')
    .action(async (options: { json?: boolean; strict?: boolean; production?: boolean }) => {
      const audit = await runCommand('npm', ['audit', '--json'], process.cwd());
      const auditRecords = audit.stdout.trim().length > 0 ? parseNpmAuditJson(audit.stdout) : [];
      if (auditRecords.length > 0) {
        process.stderr.write(`npm audit advisories parsed: ${auditRecords.length}\n`);
      }
      if (audit.exitCode !== 0 && audit.stdout.trim().length === 0) {
        process.stderr.write(audit.stderr);
      }
      const report = await scanProject({
        cwd: process.cwd(),
        env: process.env,
        strict: options.strict,
        production: options.production,
        advisories: auditRecords
      });
      process.stdout.write(
        options.json ? `${JSON.stringify(report, null, 2)}\n` : renderConsoleReport(report)
      );
      process.exitCode = exitCodeForFindings(report.findings, options.strict);
    });
}
