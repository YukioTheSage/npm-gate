import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import type {
  AdvisoryInput,
  IntelligenceClient,
  IntelligenceSource,
  LoadedConfig,
  PackageCandidate,
  PackageManifest,
  RegistryClient,
  RiskSignal,
  ScanProjectOptions,
  ScanReport
} from './types.js';
import { loadConfig } from '../config/config-loader.js';
import { NpmRegistryClient } from '../registry/client.js';
import {
  getPublishTime,
  getVersionManifest,
  nearestPreviousVersion
} from '../registry/metadata.js';
import { releaseAgeSignal } from '../analyzers/release-age-analyzer.js';
import { lifecycleSignals } from '../analyzers/lifecycle-script-analyzer.js';
import { manifestBehaviorSignals } from '../analyzers/behavior-rules.js';
import { dependencyDiffSignals } from '../analyzers/dependency-diff-analyzer.js';
import { detectNameConfusion } from '../analyzers/name-confusion-analyzer.js';
import {
  collectManifestDependencies,
  readPackageManifest
} from '../analyzers/manifest-analyzer.js';
import { scanLockfiles } from '../analyzers/lockfile-analyzer.js';
import { discoverDependencyFiles } from '../analyzers/file-discovery.js';
import {
  advisorySignals,
  loadLocalAdvisoryFeed,
  matchLocalAdvisories
} from '../analyzers/advisory-analyzer.js';
import { provenanceSignal } from '../analyzers/provenance-analyzer.js';
import { signatureSignal } from '../analyzers/signature-analyzer.js';
import { analyzeLocalSourceCandidate } from '../analyzers/local-source-analyzer.js';
import {
  inspectRegistryPackageTarball,
  type RegistryPackageTarballInspection
} from '../registry/tarball.js';
import { analyzeLockfileSecurity } from '../analyzers/lockfile-security-analyzer.js';
import { analyzeGitHubWorkflows } from '../analyzers/workflow-analyzer.js';
import { resolveDependencyClosure } from '../analyzers/dependency-closure-analyzer.js';
import { OsvIntelligenceClient } from '../intelligence/osv-client.js';
import { decidePackage } from '../policy/policy-engine.js';
import { loadAllowlist } from '../policy/allowlist.js';
import { applyExceptions, loadExceptions } from '../policy/exceptions.js';
import { createJsonReport } from '../reporting/json-reporter.js';
import { pathExists } from '../utils/fs.js';
import { parsePackageRef } from '../utils/package-ref.js';

const TOOL_VERSION = '0.1.0';

interface EvaluationContext {
  loaded: LoadedConfig;
  intelligence?: IntelligenceClient;
  tarballCache: Map<string, Promise<RegistryPackageTarballInspection | undefined>>;
  intelligenceFailures: Map<IntelligenceSource, RiskSignal>;
  transitiveEvaluated: Set<string>;
}

interface EvaluatedPackage {
  candidate: PackageCandidate;
  signals: RiskSignal[];
}

async function readLocalAdvisories(cwd: string) {
  const path = join(cwd, 'npm-gate-advisories.json');
  return (await pathExists(path)) ? loadLocalAdvisoryFeed(path) : { packages: [] };
}

async function combinedAdvisories(options: ScanProjectOptions): Promise<AdvisoryInput[]> {
  const local = await readLocalAdvisories(options.cwd);
  return [...local.packages, ...(options.advisories ?? [])];
}

function configProfile(options: ScanProjectOptions) {
  return options.production ? 'production' : undefined;
}

async function projectCandidates(cwd: string): Promise<PackageCandidate[]> {
  const manifestPath = join(cwd, 'package.json');
  const dependencyFiles = new Set(await discoverDependencyFiles(cwd));
  const candidates: PackageCandidate[] = [];
  if (dependencyFiles.has('package.json') && (await pathExists(manifestPath))) {
    const manifest = await readPackageManifest(manifestPath);
    candidates.push(
      ...collectManifestDependencies(manifest).map((dependency) => {
        const parsed = parsePackageRef(dependency.spec);
        return {
          name: dependency.name,
          requested: dependency.spec,
          spec: parsed.type === 'registry' ? dependency.spec : parsed.spec,
          dependencyType: dependency.section,
          source: 'package.json',
          sourceType: parsed.sourceType
        };
      })
    );
  }
  candidates.push(...(await scanLockfiles(cwd)));

  const byName = new Map<string, PackageCandidate>();
  for (const candidate of candidates) {
    const key = `${candidate.name}:${candidate.version ?? candidate.spec ?? ''}`;
    if (!byName.has(key)) byName.set(key, candidate);
  }
  return [...byName.values()];
}

function nameConfusionSignal(
  candidate: PackageCandidate,
  protectedNames: string[]
): RiskSignal | undefined {
  const finding = detectNameConfusion(candidate.name, protectedNames);
  if (!finding) return undefined;
  return {
    id: 'name-confusion',
    score: finding.confidence === 'high' ? 45 : 30,
    severity: finding.confidence === 'high' ? 'high' : 'medium',
    message: finding.explanation,
    evidence: [{ type: 'name-confusion', message: finding.explanation, value: finding }],
    remediation: ['Verify the package name and prefer allowlisted protected dependencies.'],
    canOverride: true
  };
}

function gitDependencySignal(candidate: PackageCandidate): RiskSignal | undefined {
  const spec = candidate.spec ?? candidate.requested;
  if (!spec) return undefined;
  const parsed = candidate.sourceType === 'git' ? undefined : parsePackageRef(spec);
  if (candidate.sourceType !== 'git' && parsed?.type !== 'git') return undefined;
  return {
    id: 'git-dependency',
    score: 35,
    severity: 'high',
    message: `Git dependency requested: ${spec}`,
    evidence: [{ type: 'dependency-spec', message: 'Git dependency spec', value: spec }],
    remediation: ['Use a reviewed registry release or pin an immutable commit.'],
    canOverride: true
  };
}

async function evaluateCandidate(
  candidate: PackageCandidate,
  registry: RegistryClient,
  options: ScanProjectOptions,
  context: EvaluationContext
): Promise<EvaluatedPackage[]> {
  const loaded = context.loaded;
  const signals: RiskSignal[] = [];

  const localSourceAnalysis = await analyzeLocalSourceCandidate(candidate, options.cwd, registry);
  if (localSourceAnalysis) return [localSourceAnalysis];

  const gitSignal = gitDependencySignal(candidate);
  if (gitSignal) signals.push(gitSignal);
  if (candidate.sourceType === 'git') return [{ candidate, signals }];

  try {
    const metadata = await registry.getPackageMetadata(candidate.name);
    const version =
      candidate.version ?? (await registry.resolveVersion(candidate.name, candidate.spec));
    const versionManifest = getVersionManifest(metadata, version);
    const previousVersion = nearestPreviousVersion(metadata, version);
    const previousManifest = previousVersion
      ? getVersionManifest(metadata, previousVersion)
      : undefined;
    const current: PackageManifest = versionManifest ?? { name: candidate.name, version };
    const versionCount = Object.keys(metadata.versions).length;

    candidate.version = version;
    signals.push(...lifecycleSignals(current, previousManifest));
    signals.push(...manifestBehaviorSignals(current));
    signals.push(...dependencyDiffSignals(previousManifest, current));

    const releaseSignal = releaseAgeSignal(
      getPublishTime(metadata, version),
      loaded.policy.minimumReleaseAgeHours,
      options.now
    );
    if (releaseSignal) signals.push(releaseSignal);

    const confusion = nameConfusionSignal(candidate, loaded.policy.protectedPackageNames);
    if (confusion) signals.push(confusion);

    const advisoryFeed = { packages: await combinedAdvisories(options) };
    signals.push(...advisorySignals(matchLocalAdvisories(advisoryFeed, candidate.name, version)));

    const intelligence = await intelligenceSignals(
      context,
      loaded.policy.requiredIntelligenceSources,
      candidate.name,
      version
    );
    signals.push(...intelligence);

    const requiresProvenance =
      loaded.policy.requireProvenanceForHighImpactPackages &&
      loaded.policy.highImpactPackageNames.includes(candidate.name);
    const provenance = provenanceSignal(current, candidate.name, requiresProvenance);
    if (provenance) signals.push(provenance);
    const signature = signatureSignal(
      current,
      loaded.policy.warnMissingRegistrySignature,
      requiresProvenance
    );
    if (signature) signals.push(signature);

    if (options.analyzeTarballs || loaded.policy.requireTarballInspection) {
      signals.push(
        ...(await registryTarballSignals({
          registry,
          cache: context.tarballCache,
          manifest: current,
          requireTarballInspection: loaded.policy.requireTarballInspection,
          requireIntegrityMatch: loaded.policy.requireIntegrityMatch
        }))
      );
    }

    if (versionCount <= 1) {
      signals.push({
        id: 'low-version-history',
        score: 12,
        severity: 'low',
        message: 'Package has very low version history',
        evidence: [{ type: 'registry-metadata', message: 'Version count', value: versionCount }],
        remediation: ['Review maintainer and package history before trusting the release.'],
        canOverride: true
      });
    }

    if (!metadata.time?.[version]) {
      signals.push({
        id: 'registry-metadata-inconsistency',
        score: 20,
        severity: 'medium',
        message: 'Registry metadata is missing publish time for resolved version',
        evidence: [
          {
            type: 'registry-metadata',
            message: 'Missing time field',
            value: { package: candidate.name, version }
          }
        ],
        remediation: ['Retry registry metadata lookup or require review before install.'],
        canOverride: true
      });
    }

    const evaluated: EvaluatedPackage[] = [{ candidate, signals }];
    if (loaded.policy.inspectTransitiveDependencies) {
      try {
        evaluated.push(
          ...(await evaluateTransitiveDependencies(current, registry, options, context))
        );
      } catch (error) {
        signals.push(dependencyClosureUninspectable(candidate, error));
      }
    }

    return evaluated;
  } catch (error) {
    signals.push({
      id: 'unknown-package',
      score: 20,
      severity: 'medium',
      message: `Unable to resolve registry metadata for ${candidate.name}`,
      evidence: [
        {
          type: 'registry-error',
          message: error instanceof Error ? error.message : 'Unknown error'
        }
      ],
      remediation: ['Check registry connectivity or require review for unknown packages.'],
      canOverride: true
    });
  }

  return [{ candidate, signals }];
}

function evidenceValueWithDependencyPath(value: unknown, dependencyPath: string[]): unknown {
  const dependencyPathText = dependencyPath.join(' -> ');
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return { ...value, dependencyPath, dependencyPathText };
  }
  return { value, dependencyPath, dependencyPathText };
}

function withDependencyPath(signals: RiskSignal[], dependencyPath: string[]): RiskSignal[] {
  return signals.map((signal) => ({
    ...signal,
    evidence: (signal.evidence ?? []).map((evidence) => ({
      ...evidence,
      value: evidenceValueWithDependencyPath(evidence.value, dependencyPath)
    }))
  }));
}

function dependencyClosureUninspectable(
  candidate: PackageCandidate,
  error: unknown
): RiskSignal {
  return {
    id: 'dependency-closure-uninspectable',
    score: 70,
    severity: 'high',
    message: 'Unable to inspect transitive dependency closure',
    evidence: [
      {
        type: 'dependency-closure',
        message: candidate.name,
        value: error instanceof Error ? error.message : String(error)
      }
    ],
    remediation: ['Do not install until transitive dependency inspection succeeds.'],
    canOverride: false
  };
}

async function evaluateTransitiveDependencies(
  rootManifest: PackageManifest,
  registry: RegistryClient,
  options: ScanProjectOptions,
  context: EvaluationContext
): Promise<EvaluatedPackage[]> {
  const loaded = context.loaded;
  const closure = await resolveDependencyClosure({
    manifest: rootManifest,
    registry,
    maxPackages: loaded.policy.maxDependencyClosurePackages
  });
  const evaluated: EvaluatedPackage[] = [];

  for (const dependency of closure) {
    const key = `${dependency.name}@${dependency.version}`;
    if (context.transitiveEvaluated.has(key)) continue;
    context.transitiveEvaluated.add(key);

    const previousVersion = nearestPreviousVersion(dependency.metadata, dependency.version);
    const previousManifest = previousVersion
      ? getVersionManifest(dependency.metadata, previousVersion)
      : undefined;
    const signals: RiskSignal[] = [
      ...lifecycleSignals(dependency.manifest, previousManifest),
      ...manifestBehaviorSignals(dependency.manifest),
      ...dependencyDiffSignals(previousManifest, dependency.manifest)
    ];

    const releaseSignal = releaseAgeSignal(
      getPublishTime(dependency.metadata, dependency.version),
      loaded.policy.minimumReleaseAgeHours,
      options.now
    );
    if (releaseSignal) signals.push(releaseSignal);

    const confusion = nameConfusionSignal(
      { name: dependency.name, version: dependency.version },
      loaded.policy.protectedPackageNames
    );
    if (confusion) signals.push(confusion);

    const advisoryFeed = { packages: await combinedAdvisories(options) };
    signals.push(
      ...advisorySignals(
        matchLocalAdvisories(advisoryFeed, dependency.name, dependency.version)
      )
    );

    signals.push(
      ...(await intelligenceSignals(
        context,
        loaded.policy.requiredIntelligenceSources,
        dependency.name,
        dependency.version
      ))
    );

    const requiresProvenance =
      loaded.policy.requireProvenanceForHighImpactPackages &&
      loaded.policy.highImpactPackageNames.includes(dependency.name);
    const provenance = provenanceSignal(dependency.manifest, dependency.name, requiresProvenance);
    if (provenance) signals.push(provenance);
    const signature = signatureSignal(
      dependency.manifest,
      loaded.policy.warnMissingRegistrySignature,
      requiresProvenance
    );
    if (signature) signals.push(signature);

    if (options.analyzeTarballs || loaded.policy.requireTarballInspection) {
      signals.push(
        ...(await registryTarballSignals({
          registry,
          cache: context.tarballCache,
          manifest: dependency.manifest,
          requireTarballInspection: loaded.policy.requireTarballInspection,
          requireIntegrityMatch: loaded.policy.requireIntegrityMatch
        }))
      );
    }

    if (Object.keys(dependency.metadata.versions).length <= 1) {
      signals.push({
        id: 'low-version-history',
        score: 12,
        severity: 'low',
        message: 'Package has very low version history',
        evidence: [
          {
            type: 'registry-metadata',
            message: 'Version count',
            value: Object.keys(dependency.metadata.versions).length
          }
        ],
        remediation: ['Review maintainer and package history before trusting the release.'],
        canOverride: true
      });
    }

    if (!dependency.metadata.time?.[dependency.version]) {
      signals.push({
        id: 'registry-metadata-inconsistency',
        score: 20,
        severity: 'medium',
        message: 'Registry metadata is missing publish time for resolved version',
        evidence: [
          {
            type: 'registry-metadata',
            message: 'Missing time field',
            value: { package: dependency.name, version: dependency.version }
          }
        ],
        remediation: ['Retry registry metadata lookup or require review before install.'],
        canOverride: true
      });
    }

    evaluated.push({
      candidate: {
        name: dependency.name,
        version: dependency.version,
        spec: dependency.version,
        source: 'transitive',
        sourceType: 'registry'
      },
      signals: withDependencyPath(signals, dependency.dependencyPath)
    });
  }

  return evaluated;
}

function requiredIntelligenceUnavailable(source: IntelligenceSource, error: unknown): RiskSignal {
  return {
    id: 'required-intelligence-unavailable',
    score: 70,
    severity: 'high',
    message: `Required intelligence source is unavailable: ${source}`,
    evidence: [
      {
        type: 'intelligence-source',
        message: `Unable to query ${source}`,
        value: error instanceof Error ? error.message : String(error)
      }
    ],
    remediation: [
      'Restore the required intelligence source or remove it from policy after review.'
    ],
    canOverride: false
  };
}

async function intelligenceSignals(
  context: EvaluationContext,
  requiredSources: IntelligenceSource[],
  name: string,
  version: string
): Promise<RiskSignal[]> {
  if (!context.intelligence) {
    if (requiredSources.includes('osv')) {
      const signal = requiredIntelligenceUnavailable(
        'osv',
        'No OSV intelligence client configured'
      );
      context.intelligenceFailures.set('osv', signal);
      return [signal];
    }
    return [];
  }

  try {
    const records = await context.intelligence.queryVulnerabilities([{ name, version }]);
    return advisorySignals(records);
  } catch (error) {
    if (requiredSources.includes('osv')) {
      const signal = requiredIntelligenceUnavailable('osv', error);
      context.intelligenceFailures.set('osv', signal);
      return [signal];
    }
    return [];
  }
}

function registryTarballUninspectable(message: string, value?: unknown): RiskSignal {
  return {
    id: 'registry-tarball-uninspectable',
    score: 70,
    severity: 'high',
    message,
    evidence: [{ type: 'registry-tarball', message, value }],
    remediation: [
      'Do not install until the package tarball can be inspected.',
      'Retry against a trusted registry mirror.'
    ],
    canOverride: false
  };
}

async function registryTarballSignals(input: {
  registry: RegistryClient;
  cache: Map<string, Promise<RegistryPackageTarballInspection | undefined>>;
  manifest: PackageManifest;
  requireTarballInspection: boolean;
  requireIntegrityMatch: boolean;
}): Promise<RiskSignal[]> {
  const tarballUrl = input.manifest.dist?.tarball;
  if (!tarballUrl) {
    return input.requireTarballInspection
      ? [
          registryTarballUninspectable('Registry metadata does not include a package tarball URL', {
            package: input.manifest.name,
            version: input.manifest.version
          })
        ]
      : [];
  }

  const integrity = input.requireIntegrityMatch ? input.manifest.dist?.integrity : undefined;
  const key = `${input.manifest.name ?? 'unknown'}@${input.manifest.version ?? 'unknown'}:${integrity ?? tarballUrl}`;
  try {
    let inspection = input.cache.get(key);
    if (!inspection) {
      inspection = inspectRegistryPackageTarball(input.registry, tarballUrl, integrity);
      input.cache.set(key, inspection);
    }
    const result = await inspection;
    if (!result) {
      return input.requireTarballInspection
        ? [
            registryTarballUninspectable(
              'Registry client cannot fetch package tarballs',
              tarballUrl
            )
          ]
        : [];
    }
    if (!result.manifest) {
      return [
        ...result.signals,
        registryTarballUninspectable('Registry tarball package.json is missing', tarballUrl)
      ];
    }
    return [
      ...result.signals,
      ...lifecycleSignals(result.manifest, result.manifest),
      ...manifestBehaviorSignals(result.manifest)
    ];
  } catch (error) {
    return [registryTarballUninspectable('Unable to inspect registry package tarball', error)];
  }
}

function approvedRegistryHosts(policyHosts: string[], env: ScanProjectOptions['env']): string[] {
  const hosts = new Set(policyHosts);
  const registryUrl = env?.npm_config_registry ?? env?.NPM_CONFIG_REGISTRY;
  if (registryUrl) {
    try {
      hosts.add(new URL(registryUrl).hostname);
    } catch {
      // Ignore invalid registry URLs here; registry client reports those failures separately.
    }
  }
  return [...hosts];
}

async function projectPolicySignals(
  options: ScanProjectOptions,
  loaded: LoadedConfig
): Promise<Array<{ candidate: PackageCandidate; signals: RiskSignal[] }>> {
  const findings: Array<{ candidate: PackageCandidate; signals: RiskSignal[] }> = [];
  const lockfileSignals = await analyzeLockfileSecurity(options.cwd, {
    approvedRegistryHosts: approvedRegistryHosts(loaded.policy.approvedRegistryHosts, options.env),
    previousPackageLockPath:
      options.previousPackageLockPath ?? options.env?.NPM_GATE_BASE_PACKAGE_LOCK
  });
  if (lockfileSignals.length > 0) {
    findings.push({
      candidate: { name: 'lockfile:package-lock.json', source: 'package-lock.json' },
      signals: lockfileSignals
    });
  }

  if (loaded.policy.requireWorkflowShaPinning || loaded.policy.forbidReleaseCaches) {
    const workflowSignals = await analyzeGitHubWorkflows(options.cwd, {
      requireWorkflowShaPinning: loaded.policy.requireWorkflowShaPinning,
      forbidReleaseCaches: loaded.policy.forbidReleaseCaches
    });
    if (workflowSignals.length > 0) {
      findings.push({
        candidate: { name: 'workflow:.github/workflows', source: '.github/workflows' },
        signals: workflowSignals
      });
    }
  }

  return findings;
}

export async function evaluatePackages(
  options: ScanProjectOptions & { candidates: PackageCandidate[] }
): Promise<ScanReport> {
  const loaded = await loadConfig({
    cwd: options.cwd,
    env: options.env,
    profile: configProfile(options)
  });
  const registry =
    options.registry ??
    new NpmRegistryClient({
      cwd: options.cwd,
      registryUrl: options.env?.npm_config_registry ?? options.env?.NPM_CONFIG_REGISTRY
    });
  const allowlist = await loadAllowlist(options.cwd);
  const exceptions = await loadExceptions(options.cwd);
  const findings = [];
  const context: EvaluationContext = {
    loaded,
    intelligence:
      options.intelligence ??
      (loaded.policy.requiredIntelligenceSources.includes('osv')
        ? new OsvIntelligenceClient()
        : undefined),
    tarballCache: new Map(),
    intelligenceFailures: new Map(),
    transitiveEvaluated: new Set()
  };

  for (const candidate of options.candidates) {
    const evaluatedPackages = await evaluateCandidate(candidate, registry, options, context);
    for (const evaluated of evaluatedPackages) {
      const allowlisted = Boolean(
        allowlist.match(evaluated.candidate.name, evaluated.candidate.version, options.now)
      );
      if (loaded.mode === 'ci' && loaded.policy.blockNewPackageNamesInCI && !allowlisted) {
        evaluated.signals.push({
          id: 'new-package-name-ci',
          score: 40,
          severity: 'high',
          message: `${evaluated.candidate.name} is not allowlisted in CI mode`,
          evidence: [{ type: 'allowlist', message: 'No matching CI allowlist entry found' }],
          remediation: [
            'Add a justified allowlist entry after review or pin an approved dependency.'
          ],
          canOverride: false
        });
      }
      findings.push(
        decidePackage({
          candidate: evaluated.candidate,
          policy: loaded.policy,
          mode: loaded.mode,
          strict: options.strict,
          allowlisted,
          signals: evaluated.signals
        })
      );
    }
  }

  for (const [source, signal] of context.intelligenceFailures) {
    findings.push(
      decidePackage({
        candidate: { name: `intelligence:${source}` },
        policy: loaded.policy,
        mode: loaded.mode,
        strict: options.strict,
        signals: [signal]
      })
    );
  }

  for (const projectFinding of await projectPolicySignals(options, loaded)) {
    findings.push(
      decidePackage({
        candidate: projectFinding.candidate,
        policy: loaded.policy,
        mode: loaded.mode,
        strict: options.strict,
        signals: projectFinding.signals
      })
    );
  }

  return createJsonReport({
    startedAt: (options.now ?? new Date()).toISOString(),
    toolVersion: TOOL_VERSION,
    mode: loaded.mode,
    policyPath: loaded.path,
    configSource: loaded.source,
    findings: applyExceptions(exceptions, findings, options.now)
  });
}

export async function scanProject(options: ScanProjectOptions): Promise<ScanReport> {
  return evaluatePackages({ ...options, candidates: await projectCandidates(options.cwd) });
}

export async function readProjectPackageJson(cwd: string): Promise<PackageManifest | undefined> {
  const path = join(cwd, 'package.json');
  if (!(await pathExists(path))) return undefined;
  return JSON.parse(await readFile(path, 'utf8')) as PackageManifest;
}
