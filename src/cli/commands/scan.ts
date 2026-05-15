import type { Command } from 'commander';
import type { PolicyMode } from '../../core/types.js';
import { scanProject } from '../../core/engine.js';
import { exitCodeForFindings, strictExitForReport } from '../../core/decision.js';
import { renderConsoleReport } from '../../reporting/console-reporter.js';
import { createSarifReport } from '../../reporting/sarif-reporter.js';

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan package manifests and lockfiles without installing dependencies')
    .option('--json', 'print JSON report')
    .option('--strict', 'fail on warnings and blocks')
    .option('--tarballs', 'download and statically inspect package tarballs')
    .option('--deep-tarballs', 'also inspect tarballs for transitive dependency closure')
    .option('--production', 'use production hardening profile')
    .option('--policy-mode <mode>', 'policy mode: balanced, strict, or emergency')
    .action(
      async (options: {
        json?: boolean;
        strict?: boolean;
        tarballs?: boolean;
        deepTarballs?: boolean;
        production?: boolean;
        policyMode?: PolicyMode;
      }) => {
        const report = await scanProject({
          cwd: process.cwd(),
          env: process.env,
          strict: options.strict,
          policyMode: options.policyMode,
          production: options.production,
          analyzeTarballs: options.tarballs || options.deepTarballs,
          deepTarballInspection: options.deepTarballs
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

  program
    .command('report')
    .description('Generate a dependency risk report')
    .option('--format <format>', 'console, json, or sarif', 'console')
    .option('--strict', 'fail on warnings and blocks')
    .option('--deep-tarballs', 'also inspect tarballs for transitive dependency closure')
    .option('--production', 'use production hardening profile')
    .option('--policy-mode <mode>', 'policy mode: balanced, strict, or emergency')
    .action(
      async (options: {
        format: string;
        strict?: boolean;
        deepTarballs?: boolean;
        production?: boolean;
        policyMode?: PolicyMode;
      }) => {
        const report = await scanProject({
          cwd: process.cwd(),
          env: process.env,
          strict: options.strict,
          policyMode: options.policyMode,
          production: options.production,
          analyzeTarballs: options.deepTarballs,
          deepTarballInspection: options.deepTarballs
        });
        if (options.format === 'json') process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
        else if (options.format === 'sarif')
          process.stdout.write(`${JSON.stringify(createSarifReport(report), null, 2)}\n`);
        else process.stdout.write(renderConsoleReport(report));
        process.exitCode = exitCodeForFindings(
          report.findings,
          strictExitForReport(report, options.strict)
        );
      }
    );
}
