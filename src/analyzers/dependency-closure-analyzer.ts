import type { PackageManifest, PackageMetadata, RegistryClient } from '../core/types.js';
import { getVersionManifest } from '../registry/metadata.js';

export interface ResolvedDependency {
  name: string;
  version: string;
  manifest: PackageManifest;
  metadata: PackageMetadata;
  dependencyPath: string[];
}

export interface ResolveDependencyClosureInput {
  manifest: PackageManifest;
  registry: RegistryClient;
  maxPackages: number;
}

interface PendingDependency {
  name: string;
  range: string;
  dependencyPath: string[];
}

function manifestLabel(manifest: PackageManifest): string {
  return `${manifest.name ?? 'unknown'}@${manifest.version ?? 'unknown'}`;
}

function dependencyEntries(manifest: PackageManifest): Array<[string, string]> {
  return [
    ...Object.entries(manifest.dependencies ?? {}),
    ...Object.entries(manifest.optionalDependencies ?? {})
  ];
}

export async function resolveDependencyClosure(
  input: ResolveDependencyClosureInput
): Promise<ResolvedDependency[]> {
  const root = manifestLabel(input.manifest);
  const queue: PendingDependency[] = dependencyEntries(input.manifest).map(([name, range]) => ({
    name,
    range,
    dependencyPath: [root]
  }));
  const seen = new Set<string>();
  const resolved: ResolvedDependency[] = [];

  for (let index = 0; index < queue.length; index += 1) {
    const next = queue[index]!;
    const version = await input.registry.resolveVersion(next.name, next.range);
    const key = `${next.name}@${version}`;
    if (seen.has(key)) continue;

    if (resolved.length + 1 > input.maxPackages) {
      throw new Error(
        `Dependency closure exceeds configured maximum of ${input.maxPackages} packages`
      );
    }

    seen.add(key);
    const metadata = await input.registry.getPackageMetadata(next.name);
    const manifest = getVersionManifest(metadata, version) ?? {
      name: next.name,
      version
    };
    const dependencyPath = [...next.dependencyPath, key];
    resolved.push({ name: next.name, version, manifest, metadata, dependencyPath });

    for (const [name, range] of dependencyEntries(manifest)) {
      queue.push({ name, range, dependencyPath });
    }
  }

  return resolved;
}
