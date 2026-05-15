import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { RiskSignal } from '../core/types.js';
import { pathExists } from '../utils/fs.js';

export interface CredentialExposureInput {
  cwd: string;
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
}

const envCategories: Array<{ category: string; variables: string[] }> = [
  { category: 'npm-token-env', variables: ['NPM_TOKEN', 'NODE_AUTH_TOKEN'] },
  { category: 'github-token-env', variables: ['GITHUB_TOKEN', 'GH_TOKEN'] },
  {
    category: 'cloud-credential-env',
    variables: [
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'GOOGLE_APPLICATION_CREDENTIALS',
      'AZURE_CLIENT_SECRET'
    ]
  }
];

function signal(category: string, value: unknown): RiskSignal {
  return {
    id: 'credential-exposure',
    score: 25,
    severity: 'medium',
    riskCategory: 'credential_exposure_risk',
    matchedSignals: [category],
    message: `Credential exposure category detected: ${category}`,
    evidence: [{ type: 'credential-category', message: category, value }],
    remediation: [
      'Run dependency installation with no tokens, no SSH agent, no browser profile, and no wallet access.'
    ],
    canOverride: true
  };
}

export async function analyzeCredentialExposure(
  input: CredentialExposureInput
): Promise<RiskSignal[]> {
  const signals: RiskSignal[] = [];
  const env = input.env ?? {};

  for (const category of envCategories) {
    const variables = category.variables.filter((name) => Boolean(env[name]));
    if (variables.length > 0) {
      signals.push(signal(category.category, { variables }));
    }
  }

  if (env.SSH_AUTH_SOCK) {
    signals.push(signal('ssh-agent', { present: true }));
  }
  if (env.CI) {
    signals.push(signal('ci-secrets-context', { present: true }));
  }

  const npmrcPath = join(input.cwd, '.npmrc');
  if (await pathExists(npmrcPath)) {
    const npmrc = await readFile(npmrcPath, 'utf8');
    if (/_authToken\s*=|_auth\s*=|\/\/[^:\s]+:\s*/i.test(npmrc)) {
      signals.push(signal('npmrc-token', { file: '.npmrc' }));
    }
  }

  for (const sensitivePath of ['.ssh', '.aws', '.config', 'AppData']) {
    if (await pathExists(join(input.cwd, sensitivePath))) {
      signals.push(signal('sensitive-local-path', { path: sensitivePath }));
    }
  }

  return signals;
}
