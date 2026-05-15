import type { Command } from 'commander';
import type { PolicyMode } from '../../core/types.js';
import { scanProject } from '../../core/engine.js';
import { exitCodeForFindings, strictExitForReport } from '../../core/decision.js';
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
    .option('--policy-mode <mode>', 'policy mode: balanced, strict, or emergency')
    .action(
      async (options: {
        json?: boolean;
        strict?: boolean;
        production?: boolean;
        policyMode?: PolicyMode;
      }) => {
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
          policyMode: options.policyMode,
          production: options.production,
          advisories: auditRecords
        });
        process.stdout.write(
          options.json ? `${JSON.stringify(report, null, 2)}\n` : renderConsoleReport(report)
        );
        process.exitCode = exitCodeForFindings(
          report.findings,
          strictExitForReport(report, options.strict)
        );
      }
    );
}
