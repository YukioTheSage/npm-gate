import { runPackageManager } from './package-manager-runner.js';

export function runNpm(args: string[], cwd: string): Promise<number> {
  return runPackageManager('npm', args, cwd);
}
