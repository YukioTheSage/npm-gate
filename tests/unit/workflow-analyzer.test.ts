import { mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { describe, expect, test } from 'vitest';
import { analyzeGitHubWorkflows } from '../../src/analyzers/workflow-analyzer.js';

describe('GitHub workflow analyzer', () => {
  test('flags dangerous pull_request_target workflows with untrusted checkout, cache, broad token, and unpinned actions', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-workflow-danger-'));
    const workflows = join(cwd, '.github', 'workflows');
    await mkdir(workflows, { recursive: true });
    await writeFile(
      join(workflows, 'ci.yml'),
      [
        'name: ci',
        'on: pull_request_target',
        'permissions:',
        '  contents: write',
        '  id-token: write',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: ${{ github.event.pull_request.head.sha }}',
        '      - uses: actions/cache@v4',
        '        with:',
        '          path: ~/.pnpm-store',
        '          key: ${{ runner.os }}-pnpm',
        '      - run: pnpm install'
      ].join('\n')
    );

    const signals = await analyzeGitHubWorkflows(cwd, {
      requireWorkflowShaPinning: true,
      forbidReleaseCaches: true
    });

    expect(signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'workflow-dangerous-trigger',
        'workflow-untrusted-checkout',
        'workflow-cache-poisoning-risk',
        'workflow-overprivileged-token',
        'workflow-unpinned-action'
      ])
    );
  });

  test('allows full SHA-pinned actions in ordinary pull_request workflows', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-workflow-clean-'));
    const workflows = join(cwd, '.github', 'workflows');
    await mkdir(workflows, { recursive: true });
    await writeFile(
      join(workflows, 'ci.yml'),
      [
        'name: ci',
        'on: pull_request',
        'permissions:',
        '  contents: read',
        'jobs:',
        '  test:',
        '    runs-on: ubuntu-latest',
        '    steps:',
        '      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
        '      - run: pnpm test'
      ].join('\n')
    );

    const signals = await analyzeGitHubWorkflows(cwd, {
      requireWorkflowShaPinning: true,
      forbidReleaseCaches: true
    });

    expect(signals).toEqual([]);
  });

  test('flags workflow_run artifacts, OIDC plus cache restore, self-hosted PR runners, and publish after risky install', async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'npm-gate-workflow-release-risk-'));
    const workflows = join(cwd, '.github', 'workflows');
    await mkdir(workflows, { recursive: true });
    await writeFile(
      join(workflows, 'release.yml'),
      [
        'name: release',
        'on: workflow_run',
        'permissions:',
        '  contents: write',
        '  id-token: write',
        'jobs:',
        '  publish:',
        '    runs-on: self-hosted',
        '    steps:',
        '      - uses: actions/download-artifact@v4',
        '      - uses: actions/cache@v4',
        '        with:',
        '          path: ~/.npm',
        '          key: npm-shared',
        '      - run: npm install',
        '      - run: npm publish --provenance'
      ].join('\n')
    );

    const signals = await analyzeGitHubWorkflows(cwd, {
      requireWorkflowShaPinning: true,
      forbidReleaseCaches: true
    });

    expect(signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining([
        'workflow-run-artifact-trust-boundary',
        'workflow-oidc-cache-boundary',
        'workflow-self-hosted-untrusted-runner',
        'workflow-publish-after-risky-install'
      ])
    );
  });
});
