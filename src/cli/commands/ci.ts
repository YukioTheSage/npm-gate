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
    .option('--deep-tarballs', 'also inspect tarballs for transitive dependency closure')
    .option('--release-audit', 'run release and incident audit checks, including deep tarballs')
    .option('--previous-package-lock <path>', 'compare package-lock integrity against a baseline')
    .option('--previous-pnpm-lock <path>', 'compare pnpm-lock integrity against a baseline')
    .option('--previous-yarn-lock <path>', 'compare yarn.lock integrity against a baseline')
    .action(async (options: {
      json?: boolean;
      sarif?: boolean;
      deepTarballs?: boolean;
      releaseAudit?: boolean;
      previousPackageLock?: string;
      previousPnpmLock?: string;
      previousYarnLock?: string;
    }) => {
      const env = { ...process.env, NPM_GATE_MODE: 'ci' };
      const report = await scanProject({
        cwd: process.cwd(),
        env,
        strict: true,
        policyMode: 'strict',
        production: true,
        analyzeTarballs: true,
        deepTarballInspection: Boolean(options.deepTarballs || options.releaseAudit),
        previousPackageLockPath: options.previousPackageLock,
        previousPnpmLockPath: options.previousPnpmLock,
        previousYarnLockPath: options.previousYarnLock
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
