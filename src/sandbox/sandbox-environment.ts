import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const secretEnvPatterns = [
  /^NPM_TOKEN$/i,
  /^NODE_AUTH_TOKEN$/i,
  /^GITHUB_TOKEN$/i,
  /^GH_TOKEN$/i,
  /^AWS_/i,
  /^AZURE_/i,
  /^GOOGLE_APPLICATION_CREDENTIALS$/i,
  /^SSH_AUTH_SOCK$/i
];

export interface SandboxEnvironment {
  env: Record<string, string>;
  home: string;
  limitations: string[];
}

export async function createSandboxEnvironment(input: {
  cwd: string;
  env: NodeJS.ProcessEnv | Record<string, string | undefined>;
}): Promise<SandboxEnvironment> {
  const home = await mkdtemp(join(tmpdir(), 'npm-gate-home-'));
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(input.env)) {
    if (value === undefined) continue;
    if (secretEnvPatterns.some((pattern) => pattern.test(key))) continue;
    env[key] = value;
  }
  env.HOME = home;
  env.USERPROFILE = home;
  return {
    env,
    home,
    limitations: ['network allowlisting is not enforced by npm-gate on this platform']
  };
}
