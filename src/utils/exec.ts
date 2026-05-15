import { spawn } from 'node:child_process';

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
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

export function runCommand(command: string, args: string[], cwd: string): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, shell: process.platform === 'win32' });
    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
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
