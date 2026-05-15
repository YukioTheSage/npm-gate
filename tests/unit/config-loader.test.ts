import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, test } from 'vitest';
import { loadConfig } from '../../src/config/config-loader.js';

describe('config loader', () => {
  test('loads config from current directory upward and applies environment mode override', async () => {
    const root = await mkdtemp(join(tmpdir(), 'npm-gate-'));
    const child = join(root, 'packages', 'app');
    await mkdir(child, { recursive: true });
    await writeFile(
      join(root, 'npm-gate.config.json'),
      JSON.stringify({
        minimumReleaseAgeHours: 24,
        protectedPackageNames: ['lodash']
      })
    );

    const loaded = await loadConfig({
      cwd: child,
      env: { NPM_GATE_MODE: 'ci' }
    });

    expect(loaded.policy.minimumReleaseAgeHours).toBe(24);
    expect(loaded.policy.protectedPackageNames).toEqual(['lodash']);
    expect(loaded.mode).toBe('ci');
    expect(loaded.policyMode).toBe('strict');
    expect(loaded.source).toBe('file');
  });

  test('resolves policy mode from config, strict flags, production, and emergency env', async () => {
    const balancedRoot = await mkdtemp(join(tmpdir(), 'npm-gate-balanced-policy-mode-'));
    await writeFile(
      join(balancedRoot, 'npm-gate.config.json'),
      JSON.stringify({ policyMode: 'balanced' })
    );

    const balanced = await loadConfig({
      cwd: balancedRoot,
      env: { NPM_GATE_MODE: 'warn' }
    });
    expect(balanced.policy.policyMode).toBe('balanced');
    expect(balanced.policyMode).toBe('balanced');

    const strict = await loadConfig({
      cwd: balancedRoot,
      env: { NPM_GATE_MODE: 'warn' },
      policyMode: 'strict'
    });
    expect(strict.policyMode).toBe('strict');

    const emergency = await loadConfig({
      cwd: balancedRoot,
      env: { NPM_GATE_MODE: 'warn', NPM_GATE_POLICY_MODE: 'emergency' }
    });
    expect(emergency.policyMode).toBe('emergency');

    const productionRoot = await mkdtemp(join(tmpdir(), 'npm-gate-production-policy-mode-'));
    await writeFile(join(productionRoot, 'npm-gate.config.json'), JSON.stringify({ profile: 'production' }));
    const production = await loadConfig({ cwd: productionRoot, env: { NPM_GATE_MODE: 'warn' } });
    expect(production.policyMode).toBe('strict');
  });

  test('applies production and audit-only policy profiles before explicit overrides', async () => {
    const productionRoot = await mkdtemp(join(tmpdir(), 'npm-gate-production-profile-'));
    await writeFile(
      join(productionRoot, 'npm-gate.config.json'),
      JSON.stringify({
        profile: 'production',
        protectedPackageNames: ['crypto-js'],
        approvedRegistryHosts: ['registry.npmjs.org', 'registry.company.test']
      })
    );

    const production = await loadConfig({
      cwd: productionRoot,
      env: { NPM_GATE_MODE: 'ci' }
    });

    expect(production.policy.profile).toBe('production');
    expect(production.policyMode).toBe('strict');
    expect(production.policy.requireTarballInspection).toBe(true);
    expect(production.policy.requireIntegrityMatch).toBe(true);
    expect(production.policy.inspectTransitiveDependencies).toBe(true);
    expect(production.policy.maxDependencyClosurePackages).toBe(250);
    expect(production.policy.blockCredentialHarvestingPatterns).toBe(true);
    expect(production.policy.blockInstallDownloaders).toBe(true);
    expect(production.policy.requireWorkflowShaPinning).toBe(true);
    expect(production.policy.forbidReleaseCaches).toBe(true);
    expect(production.policy.requiredIntelligenceSources).toEqual(['local']);
    expect(production.policy.protectedPackageNames).toEqual(['crypto-js']);
    expect(production.policy.approvedRegistryHosts).toEqual([
      'registry.npmjs.org',
      'registry.company.test'
    ]);

    const auditRoot = await mkdtemp(join(tmpdir(), 'npm-gate-audit-profile-'));
    await writeFile(
      join(auditRoot, 'npm-gate.config.json'),
      JSON.stringify({
        profile: 'audit-only'
      })
    );

    const auditOnly = await loadConfig({
      cwd: auditRoot,
      env: { NPM_GATE_MODE: 'warn' }
    });

    expect(auditOnly.policy.profile).toBe('audit-only');
    expect(auditOnly.policy.blockLifecycleScripts).toBe(false);
    expect(auditOnly.policy.blockKnownMaliciousAdvisories).toBe(false);
    expect(auditOnly.policy.requireTarballInspection).toBe(false);
    expect(auditOnly.policy.inspectTransitiveDependencies).toBe(false);
  });
});
