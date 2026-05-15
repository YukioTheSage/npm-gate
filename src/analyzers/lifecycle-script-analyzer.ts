import type { LifecycleScript, PackageManifest, RiskSignal } from '../core/types.js';

export const lifecycleScriptNames = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'prepublishOnly',
  'prepack',
  'postpack'
]);

const lifecycleVariantPattern =
  /^(?:pre|post)(?:install|prepare|publish|publishOnly|pack|prepack|postpack)$/;

const lifecycleRiskPatterns: Array<{
  id: string;
  label: string;
  pattern: RegExp;
  severity: RiskSignal['severity'];
  score: number;
}> = [
  {
    id: 'lifecycle-shell-pipe',
    label: 'shell pipe execution',
    pattern: /\b(?:curl|wget)\b[\s\S]{0,240}\|\s*(?:bash|sh|node|powershell|pwsh)\b/i,
    severity: 'critical',
    score: 70
  },
  {
    id: 'lifecycle-install-downloader',
    label: 'remote downloader',
    pattern: /\b(?:curl|wget|fetch\s*\(|https?\.get\s*\(|https?\.request\s*\()/i,
    severity: 'critical',
    score: 70
  },
  {
    id: 'lifecycle-powershell-downloader',
    label: 'PowerShell downloader',
    pattern: /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i,
    severity: 'critical',
    score: 70
  },
  {
    id: 'lifecycle-global-package-install',
    label: 'global package install',
    pattern: /\b(?:npm|pnpm|yarn)\s+(?:install|i|add)\s+-g\b/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'lifecycle-chmod-exec',
    label: 'chmod followed by execution',
    pattern: /\bchmod\s+\+x\b[\s\S]{0,160}(?:&&|;)\s*(?:\.\/|[A-Za-z]:?\\)/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'lifecycle-package-manager-recursion',
    label: 'package manager recursion',
    pattern: /\b(?:npm|pnpm|yarn|bun|npx)\s+(?:install|i|add|exec|x|run)\b/i,
    severity: 'high',
    score: 55
  },
  {
    id: 'lifecycle-bun-bootstrap',
    label: 'Bun or external runtime bootstrap',
    pattern: /\b(?:bun\s+(?:install|run|x)|setup_bun|bun\.sh\/install)\b/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'lifecycle-native-binary-execution',
    label: 'direct native binary execution',
    pattern: /(?:^|[\s;&|])(?:\.\/|[A-Za-z]:?\\)[^\s;&|]+\.(?:exe|dll|so|dylib|node)\b/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'lifecycle-obfuscated-payload',
    label: 'obfuscated execution payload',
    pattern: /\b(?:eval\s*\(|new\s+Function|Function\s*\(|atob\s*\(|Buffer\.from\s*\([\s\S]{0,160}base64)/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'lifecycle-shell-interpreter',
    label: 'shell interpreter invocation',
    pattern: /\b(?:bash|sh|zsh|cmd\.exe|powershell|pwsh|node\s+-e)\b/i,
    severity: 'high',
    score: 50
  }
];

export function detectLifecycleScripts(manifest: PackageManifest): LifecycleScript[] {
  return Object.entries(manifest.scripts ?? {})
    .filter(
      ([name, command]) =>
        (lifecycleScriptNames.has(name) || lifecycleVariantPattern.test(name)) &&
        typeof command === 'string' &&
        command.length > 0
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
  for (const script of scripts) {
    signals.push({
      id: 'lifecycle-script',
      score: 45,
      severity: 'high',
      riskCategory: 'lifecycle_script_risk',
      matchedSignals: [script.name],
      message: `Lifecycle script detected: ${script.name}`,
      evidence: [
        {
        type: 'manifest-script',
        message: `${script.name} script is present`,
        value: script
        }
      ],
      remediation: ['Review package tarball and upstream repository before installing.'],
      canOverride: true
    });
  }

  for (const script of newScripts) {
    signals.push({
      id: 'new-lifecycle-script',
      score: 35,
      severity: 'high',
      riskCategory: 'lifecycle_script_risk',
      matchedSignals: [script.name, 'new lifecycle script'],
      manualReview: true,
      message: `New lifecycle script introduced: ${script.name}`,
      evidence: [
        {
        type: 'manifest-diff',
        message: `${script.name} was not present in the previous version`,
        value: script
        }
      ],
      remediation: ['Pin the previous known-good version or require security review.'],
      canOverride: true
    });
  }

  for (const script of scripts) {
    for (const risk of lifecycleRiskPatterns) {
      if (!risk.pattern.test(script.command)) continue;
      signals.push({
        id: risk.id,
        score: risk.score,
        severity: risk.severity,
        riskCategory: 'lifecycle_script_risk',
        matchedSignals: [script.name, risk.label],
        message: `High-risk lifecycle script pattern detected in ${script.name}: ${risk.label}`,
        evidence: [
          {
            type: 'manifest-script',
            message: `${script.name} matches ${risk.label}`,
            value: script
          }
        ],
        remediation: ['Remove the install-time execution path or require a narrow script hash allowlist.'],
        canOverride: false
      });
    }
  }

  return signals;
}
