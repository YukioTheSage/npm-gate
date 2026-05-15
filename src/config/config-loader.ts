import { dirname, join, parse, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import type { LoadedConfig, PolicyConfig, PolicyProfile, RuntimeMode } from '../core/types.js';
import { defaultPolicy } from './default-policy.js';
import { policySchema, runtimeModeSchema } from './schema.js';

export interface LoadConfigOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
  profile?: PolicyProfile;
}

const CONFIG_FILE = 'npm-gate.config.json';

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, 'utf8')) as unknown;
}

async function findConfig(start: string): Promise<string | undefined> {
  let current = resolve(start);
  const root = parse(current).root;

  while (true) {
    const candidate = join(current, CONFIG_FILE);
    try {
      await readFile(candidate, 'utf8');
      return candidate;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    if (current === root) return undefined;
    current = dirname(current);
  }
}

function resolveMode(env: LoadConfigOptions['env']): RuntimeMode {
  const value = env?.NPM_GATE_MODE ?? 'warn';
  return runtimeModeSchema.parse(value);
}

function profileDefaults(profile: PolicyProfile): Partial<PolicyConfig> {
  if (profile === 'production') {
    return {
      profile,
      blockLifecycleScripts: true,
      warnLifecycleScripts: true,
      blockGitDependencies: true,
      warnGitDependencies: true,
      requireProvenanceForHighImpactPackages: true,
      warnMissingProvenanceWhenPreviouslyPresent: true,
      warnMissingRegistrySignature: true,
      blockNewPackageNamesInCI: true,
      blockSuspiciousNameConfusion: true,
      blockKnownMaliciousAdvisories: true,
      warnUnknownPackages: true,
      maxRiskScoreAllowed: 70,
      maxRiskScoreWarn: 35,
      allowOverridesWithJustification: true,
      disallowOverridesInCI: true,
      requiredIntelligenceSources: ['local'],
      approvedRegistryHosts: ['registry.npmjs.org'],
      requireTarballInspection: true,
      requireIntegrityMatch: true,
      inspectTransitiveDependencies: true,
      maxDependencyClosurePackages: 250,
      blockCredentialHarvestingPatterns: true,
      blockInstallDownloaders: true,
      requireWorkflowShaPinning: true,
      forbidReleaseCaches: true
    };
  }

  if (profile === 'audit-only') {
    return {
      profile,
      blockLifecycleScripts: false,
      blockGitDependencies: false,
      blockNewPackageNamesInCI: false,
      blockSuspiciousNameConfusion: false,
      blockKnownMaliciousAdvisories: false,
      requireTarballInspection: false,
      requireIntegrityMatch: false,
      inspectTransitiveDependencies: false,
      blockCredentialHarvestingPatterns: false,
      blockInstallDownloaders: false,
      requireWorkflowShaPinning: false,
      forbidReleaseCaches: false,
      maxRiskScoreAllowed: 100,
      maxRiskScoreWarn: 40
    };
  }

  return { profile };
}

export async function loadConfig(options: LoadConfigOptions): Promise<LoadedConfig> {
  const path = await findConfig(options.cwd);
  const raw = path ? await readJson(path) : {};
  const rawObject = raw as { profile?: PolicyProfile };
  const profile = options.profile ?? rawObject.profile ?? defaultPolicy.profile;
  const policy = policySchema.parse({
    ...defaultPolicy,
    ...profileDefaults(profile),
    ...rawObject,
    profile
  });

  return {
    policy,
    source: path ? 'file' : 'default',
    path,
    mode: resolveMode(options.env)
  };
}

export function defaultConfigJson(): string {
  return `${JSON.stringify(defaultPolicy, null, 2)}\n`;
}
