import semver from 'semver';
import type { PackageManifest, RiskSignal, TarballEntry } from '../core/types.js';

export interface ArtifactDiffInput {
  previousManifest?: PackageManifest;
  currentManifest: PackageManifest;
  previousEntries?: TarballEntry[];
  currentEntries?: TarballEntry[];
  previousSize?: number;
  currentSize?: number;
  sourceTagFound?: boolean;
  previousTarballUnavailable?: string;
}

const binaryExtension = /\.(?:exe|dll|so|dylib|node|elf)$/i;
const suspiciousExtension = /\.(?:ps1|sh|bash|zsh|bat|cmd)$/i;

function manifestIdentity(manifest: PackageManifest): string {
  return `${manifest.name ?? 'unknown'}@${manifest.version ?? 'unknown'}`;
}

function repositoryValue(manifest: PackageManifest | undefined): string {
  return JSON.stringify(manifest?.repository ?? null);
}

function entryMap(entries: TarballEntry[] | undefined): Map<string, TarballEntry> {
  return new Map((entries ?? []).map((entry) => [entry.path, entry]));
}

function signal(
  id: string,
  score: number,
  severity: RiskSignal['severity'],
  message: string,
  value: unknown,
  manualReview = false
): RiskSignal {
  return {
    id,
    score,
    severity,
    riskCategory: 'artifact_diff_risk',
    manualReview,
    message,
    evidence: [{ type: 'artifact-diff', message, value }],
    remediation: ['Compare the published tarball with the previous version before installing.'],
    canOverride: true
  };
}

export function artifactDiffSignals(input: ArtifactDiffInput): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const previous = input.previousManifest;
  const current = input.currentManifest;
  const previousVersion = previous?.version;
  const currentVersion = current.version;
  const releaseDiff =
    previousVersion && currentVersion ? semver.diff(previousVersion, currentVersion) : null;
  const patchOrMinor = releaseDiff === 'patch' || releaseDiff === 'minor';

  if (previous && repositoryValue(previous) !== repositoryValue(current)) {
    signals.push(
      signal(
        'source-repository-changed',
        30,
        'medium',
        'Package source repository metadata changed unexpectedly',
        { previous: previous.repository, current: current.repository },
        true
      )
    );
  }

  const previousEntries = entryMap(input.previousEntries);
  for (const entry of input.currentEntries ?? []) {
    if (previousEntries.has(entry.path)) continue;
    if (binaryExtension.test(entry.path)) {
      signals.push(
        signal(
          'new-binary-file',
          patchOrMinor ? 60 : 35,
          patchOrMinor ? 'high' : 'medium',
          `New binary file added to package tarball: ${entry.path}`,
          entry,
          true
        )
      );
    } else if (suspiciousExtension.test(entry.path)) {
      signals.push(
        signal(
          'new-suspicious-file',
          30,
          'medium',
          `New shell or PowerShell file added to package tarball: ${entry.path}`,
          entry,
          true
        )
      );
    }
  }

  if (
    patchOrMinor &&
    input.previousSize &&
    input.currentSize &&
    ((input.currentSize >= input.previousSize * 3 &&
      input.currentSize - input.previousSize >= 100_000) ||
      input.currentSize - input.previousSize >= 1_000_000)
  ) {
    signals.push(
      signal(
        'suspicious-package-size-increase',
        25,
        'medium',
        'Patch or minor release has a suspicious package size increase',
        {
          previous: input.previousSize,
          current: input.currentSize,
          package: manifestIdentity(current)
        },
        true
      )
    );
  }

  if (
    patchOrMinor &&
    input.previousEntries &&
    input.currentEntries &&
    input.currentEntries.length >= input.previousEntries.length * 3 &&
    input.currentEntries.length - input.previousEntries.length >= 20
  ) {
    signals.push(
      signal(
        'suspicious-package-file-count-increase',
        25,
        'medium',
        'Patch or minor release has a suspicious package file-count increase',
        {
          previous: input.previousEntries.length,
          current: input.currentEntries.length,
          package: manifestIdentity(current)
        },
        true
      )
    );
  }

  if (input.sourceTagFound === false && current.dist?.tarball) {
    signals.push(
      signal(
        'tarball-source-mismatch',
        70,
        'high',
        'Published tarball has no matching source tag or commit metadata',
        { package: manifestIdentity(current), tarball: current.dist.tarball },
        false
      )
    );
  }

  if (input.previousTarballUnavailable) {
    signals.push(
      signal(
        'previous-tarball-unavailable',
        25,
        'medium',
        'Previous package tarball could not be inspected for artifact diffing',
        {
          package: manifestIdentity(current),
          reason: input.previousTarballUnavailable
        },
        true
      )
    );
  }

  return signals;
}
