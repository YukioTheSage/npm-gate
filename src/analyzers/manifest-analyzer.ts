import { readFile } from 'node:fs/promises';
import type { PackageManifest } from '../core/types.js';
import { detectNewLifecycleScripts } from './lifecycle-script-analyzer.js';
import { isGitSpec } from '../utils/package-ref.js';

export const dependencySections = [
  'dependencies',
  'devDependencies',
  'peerDependencies',
  'optionalDependencies',
  'bundledDependencies',
  'bundleDependencies'
] as const;

export interface DependencyRef {
  section: string;
  name: string;
  spec: string;
}

export interface ManifestDiff {
  newLifecycleScripts: Array<{ name: string; command: string }>;
  newDependencies: DependencyRef[];
  gitDependencySwitches: Array<{
    section: string;
    name: string;
    previous: string;
    current: string;
  }>;
  changedFields: string[];
}

export async function readPackageManifest(path: string): Promise<PackageManifest> {
  return JSON.parse(await readFile(path, 'utf8')) as PackageManifest;
}

function dependenciesInSection(manifest: PackageManifest, section: string): DependencyRef[] {
  const value = manifest[section as keyof PackageManifest];
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map((name) => ({ section, name, spec: '*' }));
  }
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, string>).map(([name, spec]) => ({
      section,
      name,
      spec
    }));
  }
  return [];
}

export function collectManifestDependencies(manifest: PackageManifest): DependencyRef[] {
  return dependencySections.flatMap((section) => dependenciesInSection(manifest, section));
}

export function diffManifests(
  previousManifest: PackageManifest,
  currentManifest: PackageManifest
): ManifestDiff {
  const previousDeps = new Map(
    collectManifestDependencies(previousManifest).map((dependency) => [
      `${dependency.section}:${dependency.name}`,
      dependency
    ])
  );
  const currentDeps = collectManifestDependencies(currentManifest);

  const newDependencies = currentDeps.filter(
    (dependency) => !previousDeps.has(`${dependency.section}:${dependency.name}`)
  );

  const gitDependencySwitches = currentDeps.flatMap((dependency) => {
    const previous = previousDeps.get(`${dependency.section}:${dependency.name}`);
    if (!previous || !isGitSpec(dependency.spec) || isGitSpec(previous.spec)) return [];
    return [
      {
        section: dependency.section,
        name: dependency.name,
        previous: previous.spec,
        current: dependency.spec
      }
    ];
  });

  const watchedFields: Array<keyof PackageManifest> = [
    'scripts',
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'devDependencies',
    'bin',
    'exports',
    'main',
    'files',
    'repository'
  ];

  const changedFields = watchedFields
    .filter(
      (field) =>
        JSON.stringify(previousManifest[field] ?? null) !==
        JSON.stringify(currentManifest[field] ?? null)
    )
    .map(String);

  return {
    newLifecycleScripts: detectNewLifecycleScripts(previousManifest, currentManifest),
    newDependencies,
    gitDependencySwitches,
    changedFields
  };
}
