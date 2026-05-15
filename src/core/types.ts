export type RuntimeMode = 'off' | 'warn' | 'block' | 'ci';
export type DecisionKind = 'allow' | 'warn' | 'block';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type PolicyProfile = 'default' | 'production' | 'audit-only';
export type IntelligenceSource = 'npm-audit' | 'osv' | 'local';
export type ProvenanceStatus =
  | 'verified'
  | 'present-unverified'
  | 'missing'
  | 'unavailable'
  | 'unknown';

export interface Evidence {
  type: string;
  message: string;
  value?: unknown;
}

export interface RiskSignal {
  id: string;
  score: number;
  severity: Severity;
  message: string;
  evidence?: Evidence[];
  remediation?: string[];
  canOverride?: boolean;
}

export interface AdvisoryInput {
  name: string;
  versions: string[];
  type: 'malicious' | 'vulnerability';
  severity: Severity;
  summary: string;
}

export type PackageSourceType =
  | 'registry'
  | 'local-tarball'
  | 'local-directory'
  | 'remote-tarball'
  | 'remote-tarball-unsupported'
  | 'git';

export interface PackageCandidate {
  name: string;
  version?: string;
  requested?: string;
  dependencyType?: string;
  spec?: string;
  source?: string;
  sourceType?: PackageSourceType;
  resolvedPath?: string;
}

export interface PackageManifest {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  bundledDependencies?: string[] | Record<string, string>;
  bundleDependencies?: string[] | Record<string, string>;
  bin?: string | Record<string, string>;
  exports?: unknown;
  main?: string;
  files?: string[];
  repository?: unknown;
  dist?: {
    tarball?: string;
    shasum?: string;
    integrity?: string;
    signatures?: unknown[];
    provenance?: unknown;
  };
  deprecated?: string;
}

export interface PackageMetadata {
  name: string;
  versions: Record<string, PackageManifest>;
  time?: Record<string, string>;
  'dist-tags'?: Record<string, string>;
  maintainers?: Array<{ name: string; email?: string }>;
}

export interface RegistryClient {
  getPackageMetadata(name: string): Promise<PackageMetadata>;
  resolveVersion(name: string, range?: string): Promise<string>;
  fetchTarball?(tarballUrl: string): Promise<Buffer>;
  isSupportedTarballUrl?(tarballUrl: string): boolean;
}

export interface IntelligencePackageQuery {
  name: string;
  version?: string;
}

export interface IntelligenceClient {
  queryVulnerabilities(packages: IntelligencePackageQuery[]): Promise<AdvisoryInput[]>;
}

export interface PolicyConfig {
  profile: PolicyProfile;
  minimumReleaseAgeHours: number;
  blockLifecycleScripts: boolean;
  warnLifecycleScripts: boolean;
  blockGitDependencies: boolean;
  warnGitDependencies: boolean;
  requireProvenanceForHighImpactPackages: boolean;
  warnMissingProvenanceWhenPreviouslyPresent: boolean;
  warnMissingRegistrySignature: boolean;
  blockNewPackageNamesInCI: boolean;
  blockSuspiciousNameConfusion: boolean;
  blockKnownMaliciousAdvisories: boolean;
  warnUnknownPackages: boolean;
  maxRiskScoreAllowed: number;
  maxRiskScoreWarn: number;
  allowOverridesWithJustification: boolean;
  disallowOverridesInCI: boolean;
  protectedPackageNames: string[];
  highImpactPackageNames: string[];
  requiredIntelligenceSources: IntelligenceSource[];
  approvedRegistryHosts: string[];
  requireTarballInspection: boolean;
  requireIntegrityMatch: boolean;
  inspectTransitiveDependencies: boolean;
  maxDependencyClosurePackages: number;
  blockCredentialHarvestingPatterns: boolean;
  blockInstallDownloaders: boolean;
  requireWorkflowShaPinning: boolean;
  forbidReleaseCaches: boolean;
}

export interface LoadedConfig {
  policy: PolicyConfig;
  source: 'default' | 'file';
  path?: string;
  mode: RuntimeMode;
}

export interface PackageFinding {
  id: string;
  package: string;
  version?: string;
  decision: DecisionKind;
  severity: Severity;
  score: number;
  reasons: string[];
  evidence: Evidence[];
  remediation: string[];
  canOverride: boolean;
  suppressed?: {
    reason: string;
    exceptionId?: string;
    expiresAt?: string;
  };
}

export interface ScanReportInput {
  startedAt: string;
  toolVersion: string;
  mode: RuntimeMode;
  policyPath?: string;
  configSource: LoadedConfig['source'];
  findings: PackageFinding[];
}

export interface ScanReport extends ScanReportInput {
  summary: {
    allow: number;
    warn: number;
    block: number;
    suppressed: number;
  };
}

export interface ScanProjectOptions {
  cwd: string;
  registry?: RegistryClient;
  intelligence?: IntelligenceClient;
  env?: NodeJS.ProcessEnv | Record<string, string | undefined>;
  now?: Date;
  strict?: boolean;
  production?: boolean;
  analyzeTarballs?: boolean;
  advisories?: AdvisoryInput[];
  previousPackageLockPath?: string;
}

export interface LifecycleScript {
  name: string;
  command: string;
}

export interface TarballEntry {
  path: string;
  size: number;
  sample?: string;
}
