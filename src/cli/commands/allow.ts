import os from 'node:os';
import type { Command } from 'commander';
import { writeAllowlistEntry } from '../../policy/allowlist.js';
import { parsePackageRef } from '../../utils/package-ref.js';

export function registerAllowCommand(program: Command): void {
  program
    .command('allow <package>')
    .description('Add a justified allowlist entry for package@version or package@range')
    .requiredOption('--reason <reason>', 'ticket or justification')
    .option('--expires-at <iso>', 'optional ISO expiration')
    .action(async (packageRef: string, options: { reason: string; expiresAt?: string }) => {
      const ref = parsePackageRef(packageRef);
      if (ref.type !== 'registry') throw new Error('allow expects a registry package reference');
      await writeAllowlistEntry(process.cwd(), {
        package: ref.name,
        version: ref.range ?? '*',
        reason: options.reason,
        expiresAt: options.expiresAt,
        addedBy: os.userInfo().username,
        addedAt: new Date().toISOString()
      });
      process.stdout.write(`Allowlisted ${ref.name}@${ref.range ?? '*'}\n`);
    });
}
