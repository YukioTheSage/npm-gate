import type { Command } from 'commander';
import { loadConfig } from '../../config/config-loader.js';

export function registerDoctorCommand(program: Command): void {
  program
    .command('doctor')
    .description('Check local npm-gate environment')
    .action(async () => {
      const config = await loadConfig({ cwd: process.cwd(), env: process.env });
      process.stdout.write(
        [
          'npm-gate doctor',
          `Node: ${process.version}`,
          `Mode: ${config.mode}`,
          `Config source: ${config.source}`,
          `Config path: ${config.path ?? '(default)'}`,
          'Credential logging: redacted'
        ].join('\n') + '\n'
      );
    });
}
