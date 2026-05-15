import type { Command } from 'commander';
import { scanProject } from '../../core/engine.js';
import { exitCodeForFindings } from '../../core/decision.js';
import { createEmergencyChecklist } from '../../analyzers/emergency-analyzer.js';
import { renderConsoleReport } from '../../reporting/console-reporter.js';

function renderChecklist(): string {
  const checklist = createEmergencyChecklist();
  return [
    'Emergency next actions:',
    'Credential rotation:',
    ...checklist.credentialRotation.map((item) => `- ${item}`),
    'CI cleanup:',
    ...checklist.ciCleanup.map((item) => `- ${item}`)
  ].join('\n');
}

export function registerEmergencyCommand(program: Command): void {
  program
    .command('emergency')
    .description('Run emergency incident-response lockfile and dependency checks')
    .option('--json', 'print JSON report')
    .option('--sarif', 'reserved for future SARIF emergency output')
    .action(async (options: { json?: boolean; sarif?: boolean }) => {
      const report = await scanProject({
        cwd: process.cwd(),
        env: process.env,
        strict: true,
        policyMode: 'emergency',
        analyzeTarballs: true,
        production: true
      });

      if (options.json) {
        process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      } else {
        process.stdout.write(renderConsoleReport(report));
        process.stdout.write(`${renderChecklist()}\n`);
      }

      process.exitCode = exitCodeForFindings(report.findings, true);
    });
}
