import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { delimiter, dirname, join } from 'node:path';

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ResolvedCommandForSpawn {
  command: string;
  args: string[];
}

export interface ResolveCommandForSpawnOptions {
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
  execPath?: string;
  pathExists?: (path: string) => Promise<boolean>;
  platform?: NodeJS.Platform;
}

export interface RunCommandOptions extends ResolveCommandForSpawnOptions {
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
}

const secretPatterns: Array<[RegExp, string | ((substring: string) => string)]> = [
  [/https?:\/\/[^:\s/]+:[^@\s/]+@/gi, (match: string) => `${match.split('://')[0]}://[redacted]@`],
  [/(_authToken=)[^\s]+/gi, '$1[redacted]'],
  [/(NPM_TOKEN=)[^\s]+/gi, '$1[redacted]'],
  [/(NODE_AUTH_TOKEN=)[^\s]+/gi, '$1[redacted]'],
  [/(Authorization:\s*Bearer\s+)[^\s]+/gi, '$1[redacted]'],
  [/(token=)[^\s&]+/gi, '$1[redacted]']
];

export function redactSecrets(value: string): string {
  return secretPatterns.reduce((current, [pattern, replacement]) => {
    if (typeof replacement === 'function') {
      return current.replace(pattern, replacement);
    }
    return current.replace(pattern, replacement);
  }, value);
}

async function defaultPathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function pathEntries(
  env: NodeJS.ProcessEnv | Record<string, string | undefined>,
  platform: NodeJS.Platform
): string[] {
  const value = env.PATH ?? env.Path ?? '';
  const separator = platform === 'win32' ? ';' : delimiter;
  return value.split(separator).filter(Boolean);
}

function nodeBackedPackageManagerCli(command: string, root: string): string | undefined {
  if (command === 'npm') return join(root, 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (command === 'pnpm') return join(root, 'node_modules', 'pnpm', 'bin', 'pnpm.cjs');
  return undefined;
}

async function resolveNodeBackedPackageManagerCli(
  command: string,
  options: Required<Pick<ResolveCommandForSpawnOptions, 'env' | 'execPath' | 'platform'>> & {
    pathExists: (path: string) => Promise<boolean>;
  }
): Promise<string | undefined> {
  const roots = [...pathEntries(options.env, options.platform), dirname(options.execPath)];
  for (const root of [...new Set(roots)]) {
    const cliPath = nodeBackedPackageManagerCli(command, root);
    if (cliPath && (await options.pathExists(cliPath))) return cliPath;
  }
  return undefined;
}

export async function resolveCommandForSpawn(
  command: string,
  args: string[],
  options: ResolveCommandForSpawnOptions = {}
): Promise<ResolvedCommandForSpawn> {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const execPath = options.execPath ?? process.execPath;
  const pathExists = options.pathExists ?? defaultPathExists;

  if (platform === 'win32' && (command === 'npm' || command === 'pnpm')) {
    const cliPath = await resolveNodeBackedPackageManagerCli(command, {
      env,
      execPath,
      platform,
      pathExists
    });
    if (!cliPath) {
      throw new Error(`Unable to safely resolve ${command} CLI without invoking a shell on Windows`);
    }
    return { command: execPath, args: [cliPath, ...args] };
  }

  return { command, args };
}

export async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  options: RunCommandOptions = {}
): Promise<CommandResult> {
  const resolved = await resolveCommandForSpawn(command, args, options);
  return new Promise((resolve) => {
    const child = spawn(resolved.command, resolved.args, {
      cwd,
      shell: false,
      env: { ...process.env, ...(options.env ?? {}) }
    });
    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', (error) => {
      resolve({
        exitCode: 2,
        stdout: redactSecrets(stdout),
        stderr: redactSecrets(`${stderr}${error.message}`)
      });
    });
    child.on('close', (code) => {
      resolve({
        exitCode: code ?? 2,
        stdout: redactSecrets(stdout),
        stderr: redactSecrets(stderr)
      });
    });
  });
}
