import { Command } from 'commander';
import { ZodError } from 'zod';
import { registerAllowCommand } from './commands/allow.js';
import { registerAuditCommand } from './commands/audit.js';
import { registerCiCommand } from './commands/ci.js';
import { registerDoctorCommand } from './commands/doctor.js';
import { registerExplainCommand } from './commands/explain.js';
import { registerInstallCommands } from './commands/install.js';
import { registerConfigCommand, registerPolicyCommand } from './commands/policy.js';
import { registerScanCommand } from './commands/scan.js';

const program = new Command();

program
  .name('npm-gate')
  .description('Defensive npm supply-chain security wrapper and local scanner')
  .version('0.1.0');

registerInstallCommands(program);
registerCiCommand(program);
registerScanCommand(program);
registerPolicyCommand(program);
registerAllowCommand(program);
registerConfigCommand(program);
registerAuditCommand(program);
registerDoctorCommand(program);
registerExplainCommand(program);

program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  if (
    (error as any).code === 'commander.helpDisplayed' ||
    (error as any).code === 'commander.version'
  ) {
    process.exitCode = 0;
  } else {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = error instanceof ZodError ? 3 : ((error as any).exitCode ?? 2);
  }
}
