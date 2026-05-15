import type { PackageManifest, RiskSignal } from '../core/types.js';
import { diffManifests } from './manifest-analyzer.js';

export function dependencyDiffSignals(
  previous: PackageManifest | undefined,
  current: PackageManifest
): RiskSignal[] {
  if (!previous) return [];
  const diff = diffManifests(previous, current);
  const signals: RiskSignal[] = [];

  if (diff.newDependencies.length > 0) {
    signals.push({
      id: 'new-dependency-in-release',
      score: 20,
      severity: 'medium',
      message: `New dependency added: ${diff.newDependencies.map((dep) => dep.name).join(', ')}`,
      evidence: diff.newDependencies.map((dep) => ({
        type: 'manifest-diff',
        message: `New ${dep.section} entry ${dep.name}@${dep.spec}`,
        value: dep
      })),
      remediation: ['Review the newly introduced dependency chain.'],
      canOverride: true
    });
  }

  if (diff.gitDependencySwitches.length > 0) {
    signals.push({
      id: 'git-dependency-switch',
      score: 35,
      severity: 'high',
      message: `Dependency switched to git source: ${diff.gitDependencySwitches.map((dep) => dep.name).join(', ')}`,
      evidence: diff.gitDependencySwitches.map((dep) => ({
        type: 'manifest-diff',
        message: `${dep.name} changed from ${dep.previous} to ${dep.current}`,
        value: dep
      })),
      remediation: ['Prefer immutable registry releases or pin a reviewed commit.'],
      canOverride: true
    });
  }

  if (diff.changedFields.length > 0) {
    signals.push({
      id: 'manifest-metadata-change',
      score: Math.min(20, diff.changedFields.length * 4),
      severity: 'low',
      message: `Package metadata changed: ${diff.changedFields.join(', ')}`,
      evidence: [
        { type: 'manifest-diff', message: 'Changed manifest fields', value: diff.changedFields }
      ],
      remediation: ['Compare the package manifest with the previous version.'],
      canOverride: true
    });
  }

  return signals;
}
