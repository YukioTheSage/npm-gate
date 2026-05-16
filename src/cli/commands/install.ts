import type { Command } from 'commander';
import { evaluatePackages, scanProject } from '../../core/engine.js';
import { exitCodeForFindings, strictExitForReport } from '../../core/decision.js';
import { renderConsoleReport } from '../../reporting/console-reporter.js';
import { classifyNpmCommand } from '../../wrappers/command-classifier.js';
import {
  resolvePackageManager,
  runPackageManager
} from '../../wrappers/package-manager-runner.js';
import type { PackageCandidate, PolicyMode } from '../../core/types.js';
import { createSandboxPlan } from '../../sandbox/sandbox-plan.js';
import { createSandboxEnvironment } from '../../sandbox/sandbox-environment.js';
import { renderSandboxPlan } from '../../sandbox/sandbox-runner.js';
import { assertModeOffAllowed } from '../ci-bypass-guard.js';

interface InstallOptions {
  dryRun?: boolean;
  json?: boolean;
  strict?: boolean;
  noExecute?: boolean;
  sandboxPlan?: boolean;
  sandboxExecute?: boolean;
  production?: boolean;
  packageManager?: string;
  policyMode?: PolicyMode;
}

function candidatesFromCommand(command: string, packages: string[]): PackageCandidate[] {
  return classifyNpmCommand(command, packages).packageRefs.map((ref) => ({
    name: ref.name,
    requested: ref.raw,
    spec: ref.type === 'registry' ? ref.range : ref.spec,
    source: 'cli',
    sourceType: ref.sourceType
  }));
}

function withIgnoreScripts(args: string[]): string[] {
  return args.some((arg) => arg === '--ignore-scripts' || arg === '--ignore-scripts=true')
    ? args
    : [...args, '--ignore-scripts'];
}

function registerInstallLike(program: Command, command: string, description: string): void {
  program
    .command(`${command} [packages...]`)
    .allowUnknownOption(true)
    .description(description)
    .option('--dry-run', 'evaluate policy without running npm')
    .option('--json', 'print JSON report')
    .option('--strict', 'turn warnings into blocks')
    .option('--no-execute', 'do not run npm even if policy allows')
    .option('--sandbox-plan', 'print a non-executing sandbox plan')
    .option(
      '--sandbox-execute',
      'run the package manager with scrubbed environment and ignore-scripts defaults'
    )
    .option('--production', 'use production hardening profile')
    .option('--policy-mode <mode>', 'policy mode: balanced, strict, or emergency')
    .option('--package-manager <manager>', 'package manager to delegate to: npm or pnpm')
    .action(async (packages: string[], options: InstallOptions, cmd: Command) => {
      const allArgs = [...packages, ...cmd.args.filter((arg) => !packages.includes(arg))];
      const packageManager = await resolvePackageManager({
        cwd: process.cwd(),
        env: process.env,
        requested: options.packageManager
      });
      if (
        process.env.NPM_GATE_MODE === 'off' &&
        !options.dryRun &&
        !options.noExecute &&
        !options.sandboxExecute
      ) {
        assertModeOffAllowed(process.env);
        process.exitCode = await runPackageManager(
          packageManager,
          [command, ...allArgs],
          process.cwd()
        );
        return;
      }

      const candidates = candidatesFromCommand(command, allArgs);
      if (options.sandboxPlan) {
        if (candidates.length === 0) {
          process.stdout.write(renderSandboxPlan(createSandboxPlan('project dependencies')));
        } else {
          for (const candidate of candidates) {
            process.stdout.write(
              renderSandboxPlan(createSandboxPlan(candidate.name, candidate.version))
            );
          }
        }
      }

      const report =
        candidates.length > 0
          ? await evaluatePackages({
              cwd: process.cwd(),
              env: process.env,
              strict: options.strict,
              policyMode: options.policyMode,
              production: options.production,
              candidates
            })
          : await scanProject({
              cwd: process.cwd(),
              env: process.env,
              strict: options.strict,
              policyMode: options.policyMode,
              production: options.production
            });
      process.stdout.write(
        options.json ? `${JSON.stringify(report, null, 2)}\n` : renderConsoleReport(report)
      );
      const exitCode = exitCodeForFindings(
        report.findings,
        strictExitForReport(report, options.strict)
      );
      if (exitCode !== 0 || options.dryRun || options.noExecute || options.sandboxPlan) {
        process.exitCode = exitCode;
        return;
      }
      if (options.sandboxExecute) {
        const sandbox = await createSandboxEnvironment({ cwd: process.cwd(), env: process.env });
        process.stderr.write(`npm-gate sandbox limitation: ${sandbox.limitations.join('; ')}\n`);
        process.exitCode = await runPackageManager(
          packageManager,
          [command, ...withIgnoreScripts(allArgs)],
          process.cwd(),
          { env: sandbox.env }
        );
        return;
      }
      process.exitCode = await runPackageManager(
        packageManager,
        [command, ...allArgs],
        process.cwd()
      );
    });
}

export function registerInstallCommands(program: Command): void {
  registerInstallLike(program, 'install', 'Evaluate policy then delegate to npm install');
  registerInstallLike(
    program,
    'add',
    'Evaluate policy then delegate to npm install for add-style usage'
  );
}
