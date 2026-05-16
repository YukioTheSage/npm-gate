import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { pathExists } from '../utils/fs.js';
import { redactSecrets, resolveCommandForSpawn } from '../utils/exec.js';

export type PackageManager = 'npm' | 'pnpm';

export interface ResolvePackageManagerInput {
  cwd: string;
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
  requested?: string;
}

export interface RunPackageManagerOptions {
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
}

function parsePackageManager(value: string | undefined): PackageManager | undefined {
  if (!value) return undefined;
  if (value === 'npm' || value === 'pnpm') return value;
  throw new Error(`Unsupported package manager: ${value}`);
}

export async function resolvePackageManager(
  input: ResolvePackageManagerInput
): Promise<PackageManager> {
  const requested = parsePackageManager(input.requested);
  if (requested) return requested;

  const fromEnv = parsePackageManager(input.env?.NPM_GATE_PACKAGE_MANAGER);
  if (fromEnv) return fromEnv;

  return (await pathExists(join(input.cwd, 'pnpm-lock.yaml'))) ? 'pnpm' : 'npm';
}

export async function runPackageManager(
  packageManager: PackageManager,
  args: string[],
  cwd: string,
  options: RunPackageManagerOptions = {}
): Promise<number> {
  const env = options.env ?? process.env;
  let resolved;
  try {
    resolved = await resolveCommandForSpawn(packageManager, args, { env });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${redactSecrets(message)}\n`);
    return 2;
  }

  return new Promise((resolve) => {
    const child = spawn(resolved.command, resolved.args, {
      cwd,
      stdio: 'inherit',
      shell: false,
      env: { ...env }
    });
    child.on('error', (error) => {
      process.stderr.write(`${redactSecrets(error.message)}\n`);
      resolve(2);
    });
    child.on('close', (code) => resolve(code ?? 2));
  });
}

export async function runDefaultPackageManager(
  args: string[],
  cwd: string,
  env?: ResolvePackageManagerInput['env'],
  requested?: string
): Promise<number> {
  const packageManager = await resolvePackageManager({ cwd, env, requested });
  return runPackageManager(packageManager, args, cwd, { env });
}
