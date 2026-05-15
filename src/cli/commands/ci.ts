import type { Command } from 'commander';
import { scanProject } from '../../core/engine.js';
import { exitCodeForFindings } from '../../core/decision.js';
import { renderConsoleReport } from '../../reporting/console-reporter.js';
import { createSarifReport } from '../../reporting/sarif-reporter.js';

export function registerCiCommand(program: Command): void {
  program
    .command('ci')
    .description('Run production-grade dependency, lockfile, tarball, and workflow checks')
    .option('--json', 'print JSON report')
    .option('--sarif', 'print SARIF report')
    .option('--previous-package-lock <path>', 'compare package-lock integrity against a baseline')
    .action(async (options: { json?: boolean; sarif?: boolean; previousPackageLock?: string }) => {
      const env = { ...process.env, NPM_GATE_MODE: 'ci' };
      const report = await scanProject({
        cwd: process.cwd(),
        env,
        strict: true,
        production: true,
        analyzeTarballs: true,
        previousPackageLockPath: options.previousPackageLock
      });
      if (options.sarif) {
        process.stdout.write(`${JSON.stringify(createSarifReport(report), null, 2)}\n`);
      } else {
        process.stdout.write(
          options.json ? `${JSON.stringify(report, null, 2)}\n` : renderConsoleReport(report)
        );
      }
      process.exitCode = exitCodeForFindings(report.findings, true);
    });
}
