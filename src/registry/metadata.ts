import semver from 'semver';
import type { PackageManifest, PackageMetadata } from '../core/types.js';

export function getVersionManifest(
  metadata: PackageMetadata,
  version: string
): PackageManifest | undefined {
  return metadata.versions[version];
}

export function nearestPreviousVersion(
  metadata: PackageMetadata,
  version: string
): string | undefined {
  const versions = Object.keys(metadata.versions)
    .filter((candidate) => semver.valid(candidate) && semver.lt(candidate, version))
    .sort(semver.rcompare);
  return versions[0];
}

export function getPublishTime(metadata: PackageMetadata, version: string): string | undefined {
  return metadata.time?.[version];
}
