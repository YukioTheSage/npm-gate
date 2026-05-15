import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { describe, expect, test } from 'vitest';
import { analyzeCredentialExposure } from '../../src/analyzers/credential-exposure-analyzer.js';

describe('credential exposure analyzer', () => {
  test('reports credential categories without exposing secret values', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-credentials-'));
    await writeFile(join(cwd, '.npmrc'), '//registry.npmjs.org/:_authToken=npm_secret_value');
    await mkdir(join(cwd, '.ssh'), { recursive: true });

    const signals = await analyzeCredentialExposure({
      cwd,
      env: {
        NPM_TOKEN: 'npm_secret_value',
        GITHUB_TOKEN: 'ghs_secret_value',
        AWS_SECRET_ACCESS_KEY: 'aws_secret_value',
        SSH_AUTH_SOCK: '/tmp/agent.sock',
        CI: 'true'
      }
    });

    const serialized = JSON.stringify(signals);
    expect(serialized).toContain('npm-token-env');
    expect(serialized).toContain('github-token-env');
    expect(serialized).toContain('cloud-credential-env');
    expect(serialized).toContain('ssh-agent');
    expect(serialized).toContain('npmrc-token');
    expect(serialized).not.toContain('npm_secret_value');
    expect(serialized).not.toContain('ghs_secret_value');
    expect(serialized).not.toContain('aws_secret_value');
  });
});
