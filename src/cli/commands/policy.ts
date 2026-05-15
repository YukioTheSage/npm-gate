import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Command } from 'commander';
import { defaultConfigJson, loadConfig } from '../../config/config-loader.js';
import { evaluatePackages } from '../../core/engine.js';
import { renderConsoleReport } from '../../reporting/console-reporter.js';
import { parsePackageRef } from '../../utils/package-ref.js';
import { pathExists } from '../../utils/fs.js';

export function registerPolicyCommand(program: Command): void {
  const policy = program.command('policy').description('Manage and explain npm-gate policy');

  policy
    .command('init')
    .description('Create npm-gate.config.json')
    .action(async () => {
      const path = join(process.cwd(), 'npm-gate.config.json');
      if (await pathExists(path)) throw new Error(`${path} already exists`);
      await writeFile(path, defaultConfigJson(), 'utf8');
      process.stdout.write(`Created ${path}\n`);
    });

  policy
    .command('explain <package>')
    .description('Explain policy evaluation for package@version')
    .option('--json', 'print JSON')
    .action(async (packageRef: string, options: { json?: boolean }) => {
      const ref = parsePackageRef(packageRef);
      if (ref.type !== 'registry')
        throw new Error('policy explain expects a registry package reference');
      const report = await evaluatePackages({
        cwd: process.cwd(),
        env: process.env,
        candidates: [{ name: ref.name, requested: ref.raw, spec: ref.range, source: 'cli' }]
      });
      process.stdout.write(
        options.json ? `${JSON.stringify(report, null, 2)}\n` : renderConsoleReport(report)
      );
    });
}

export function registerConfigCommand(program: Command): void {
  const config = program.command('config').description('Inspect npm-gate configuration');
  config
    .command('show')
    .description('Show resolved configuration')
    .action(async () => {
      process.stdout.write(
        `${JSON.stringify(await loadConfig({ cwd: process.cwd(), env: process.env }), null, 2)}\n`
      );
    });
}
