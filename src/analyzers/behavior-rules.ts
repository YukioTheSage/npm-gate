import type { PackageManifest, RiskSignal } from '../core/types.js';
import { collectManifestDependencies } from './manifest-analyzer.js';
import { isGitSpec } from '../utils/package-ref.js';

export function manifestBehaviorSignals(manifest: PackageManifest): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const gitDeps = collectManifestDependencies(manifest).filter((dependency) =>
    isGitSpec(dependency.spec)
  );

  if (gitDeps.length > 0) {
    signals.push({
      id: 'git-dependency',
      score: 35,
      severity: 'high',
      message: `Git URL dependency detected: ${gitDeps.map((dependency) => dependency.name).join(', ')}`,
      evidence: gitDeps.map((dependency) => ({
        type: 'manifest-dependency',
        message: `${dependency.section}.${dependency.name} uses ${dependency.spec}`,
        value: dependency
      })),
      remediation: ['Use immutable registry dependencies or reviewed pinned commits.'],
      canOverride: true
    });
  }

  if (!manifest.repository) {
    signals.push({
      id: 'missing-repository-metadata',
      score: 8,
      severity: 'low',
      message: 'Package has no obvious source repository metadata',
      evidence: [{ type: 'manifest', message: 'repository field is missing' }],
      remediation: [
        'Review package provenance and maintainer identity before trusting the release.'
      ],
      canOverride: true
    });
  }

  return signals;
}
