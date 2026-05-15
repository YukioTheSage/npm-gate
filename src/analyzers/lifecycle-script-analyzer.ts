import type { LifecycleScript, PackageManifest, RiskSignal } from '../core/types.js';

export const lifecycleScriptNames = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepack',
  'postpack'
]);

export function detectLifecycleScripts(manifest: PackageManifest): LifecycleScript[] {
  return Object.entries(manifest.scripts ?? {})
    .filter(
      ([name, command]) =>
        lifecycleScriptNames.has(name) && typeof command === 'string' && command.length > 0
    )
    .map(([name, command]) => ({ name, command }));
}

export function detectNewLifecycleScripts(
  previousManifest: PackageManifest | undefined,
  currentManifest: PackageManifest
): LifecycleScript[] {
  const previous = new Set(
    detectLifecycleScripts(previousManifest ?? {}).map((script) => script.name)
  );
  return detectLifecycleScripts(currentManifest).filter((script) => !previous.has(script.name));
}

export function lifecycleSignals(
  manifest: PackageManifest,
  previous?: PackageManifest
): RiskSignal[] {
  const scripts = detectLifecycleScripts(manifest);
  const newScripts = detectNewLifecycleScripts(previous, manifest);

  const signals: RiskSignal[] = [];
  if (scripts.length > 0) {
    signals.push({
      id: 'lifecycle-script',
      score: 45,
      severity: 'high',
      message: `Lifecycle script detected: ${scripts.map((script) => script.name).join(', ')}`,
      evidence: scripts.map((script) => ({
        type: 'manifest-script',
        message: `${script.name} script is present`,
        value: script
      })),
      remediation: ['Review package tarball and upstream repository before installing.'],
      canOverride: true
    });
  }

  if (newScripts.length > 0) {
    signals.push({
      id: 'new-lifecycle-script',
      score: 35,
      severity: 'high',
      message: `New lifecycle script introduced: ${newScripts.map((script) => script.name).join(', ')}`,
      evidence: newScripts.map((script) => ({
        type: 'manifest-diff',
        message: `${script.name} was not present in the previous version`,
        value: script
      })),
      remediation: ['Pin the previous known-good version or require security review.'],
      canOverride: true
    });
  }

  return signals;
}
