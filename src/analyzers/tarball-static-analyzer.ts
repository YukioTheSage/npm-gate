import { isAbsolute, normalize, sep, win32 } from 'node:path';
import type { RiskSignal, TarballEntry } from '../core/types.js';
import { analyzeFrontendRuntimeEntries } from './frontend-runtime-analyzer.js';

const hiddenDirectories = new Set(['.github', '.vscode', '.claude']);
const binaryExtensions = new Set(['.exe', '.dll', '.so', '.dylib', '.node', '.elf']);
const scriptExtensions = new Set(['.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd']);

const credentialHarvestingPatterns: Array<[string, RegExp]> = [
  [
    'token environment variable',
    /\b(?:NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)\b/i
  ],
  ['credential file probe', /(?:\.npmrc|\.ssh[\\/]|id_rsa|id_ed25519|\.aws[\\/]credentials)/i],
  ['cloud metadata probe', /(?:169\.254\.169\.254|metadata\.google\.internal)/i],
  [
    'secret file enumeration',
    /\b(?:readFileSync|readFile|readdirSync|readdir|glob|fast-glob)\b[\s\S]{0,240}(?:\.npmrc|\.env|\.ssh|id_rsa|id_ed25519|\.aws|credentials|gcloud|kube[\\/]config)/i
  ],
  ['secret scanner invocation', /\btrufflehog\b/i]
];

const installDownloaderPatterns: Array<[string, RegExp]> = [
  ['bun runtime dropper', /\b(?:setup_bun|bun\s+(?:install|run|x))\b/i],
  ['curl pipe execution', /\bcurl\b[\s\S]{0,240}\|\s*(?:bash|sh|node)\b/i],
  ['wget pipe execution', /\bwget\b[\s\S]{0,240}\|\s*(?:bash|sh|node)\b/i],
  ['powershell downloader', /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i],
  ['node http downloader', /\b(?:fetch\s*\(|https?\.get\s*\(|https?\.request\s*\()/i],
  ['global npm install loader', /\bnpm\s+(?:install|i)\s+-g\b/i]
];

const networkExfilPattern =
  /\b(?:fetch\s*\(|https?\.request\s*\(|XMLHttpRequest\b|axios\.|request\s*\(|curl\b|wget\b)/i;
const childProcessPattern =
  /\b(?:child_process|exec\s*\(|execFile\s*\(|spawn\s*\(|spawnSync\s*\()/i;
const processEnvPattern = /\bprocess\.env\b/i;

const obfuscationPatterns: Array<[string, RegExp]> = [
  ['eval execution', /\beval\s*\(/i],
  ['function constructor', /\b(?:new\s+Function|Function\s*\()/i],
  ['base64 decode execution', /(?:atob\s*\(|Buffer\.from\s*\([\s\S]{0,120}base64)/i],
  ['hex escaped blob', /(?:\\x[0-9a-f]{2}){8,}/i]
];

const walletHookPatterns: Array<[string, RegExp]> = [
  ['ethereum provider hook', /window\.ethereum|ethereum\.request/i],
  ['wallet transaction method', /eth_sendTransaction|sendTransaction/i],
  ['wallet connection hook', /walletconnect|solana\.request/i]
];

function extension(path: string): string {
  const index = path.lastIndexOf('.');
  return index === -1 ? '' : path.slice(index).toLowerCase();
}

export function assertSafeTarPath(path: string): void {
  const normalized = normalize(path);
  const parts = normalized.split(/[\\/]+/);
  if (
    path.startsWith('/') ||
    isAbsolute(path) ||
    win32.isAbsolute(path) ||
    parts.includes('..') ||
    normalized.startsWith(`..${sep}`) ||
    /^[A-Za-z]:[\\/]/.test(path)
  ) {
    throw new Error(`Unsafe tar entry path rejected: ${path}`);
  }
}

function signal(
  id: string,
  score: number,
  message: string,
  entry: TarballEntry,
  severity: RiskSignal['severity']
): RiskSignal {
  return {
    id,
    score,
    severity,
    message,
    evidence: [
      { type: 'tarball-entry', message: entry.path, value: { path: entry.path, size: entry.size } }
    ],
    remediation: ['Inspect the package tarball before installation.'],
    canOverride: true
  };
}

function contentSignal(
  id: string,
  score: number,
  message: string,
  entry: TarballEntry,
  severity: RiskSignal['severity'],
  matchedPattern: string
): RiskSignal {
  return {
    id,
    score,
    severity,
    message,
    evidence: [
      {
        type: 'tarball-entry',
        message: entry.path,
        value: {
          matchedPattern,
          tarballEntry: { path: entry.path, size: entry.size }
        }
      }
    ],
    remediation: ['Do not install until the package contents are manually reviewed.'],
    canOverride: true
  };
}

function firstMatch(sample: string, patterns: Array<[string, RegExp]>): string | undefined {
  return patterns.find(([, pattern]) => pattern.test(sample))?.[0];
}

export function analyzeTarballEntries(entries: TarballEntry[]): { signals: RiskSignal[] } {
  const signals: RiskSignal[] = [];
  for (const entry of entries) {
    assertSafeTarPath(entry.path);
    const parts = entry.path.split(/[\\/]+/);
    const ext = extension(entry.path);

    if (parts.some((part) => hiddenDirectories.has(part))) {
      signals.push(
        signal(
          'hidden-directory',
          15,
          `Hidden directory found in tarball: ${entry.path}`,
          entry,
          'medium'
        )
      );
    }
    if (binaryExtensions.has(ext)) {
      signals.push(
        signal(
          'suspicious-binary',
          30,
          `Suspicious binary file found in tarball: ${entry.path}`,
          entry,
          'high'
        )
      );
    }
    if (scriptExtensions.has(ext)) {
      signals.push(
        signal(
          'suspicious-script-file',
          20,
          `Shell or PowerShell script found: ${entry.path}`,
          entry,
          'medium'
        )
      );
    }
    if (/\.min\.js$/i.test(entry.path) && entry.size > 500_000) {
      signals.push(
        signal(
          'large-minified-javascript',
          20,
          `Large minified JavaScript blob found: ${entry.path}`,
          entry,
          'medium'
        )
      );
    }
    if (/\.(?:cjs|js|mjs)$/i.test(entry.path) && entry.size > 1_000_000) {
      signals.push(
        signal(
          'large-javascript-payload',
          25,
          `Large JavaScript payload found: ${entry.path}`,
          entry,
          'medium'
        )
      );
    }

    if (!entry.sample) continue;
    const credentialMatch = firstMatch(entry.sample, credentialHarvestingPatterns);
    if (credentialMatch) {
      signals.push(
        contentSignal(
          'credential-harvesting-pattern',
          60,
          `Credential harvesting pattern found in tarball: ${entry.path}`,
          entry,
          'high',
          credentialMatch
        )
      );
    }

    const downloaderMatch = firstMatch(entry.sample, installDownloaderPatterns);
    if (downloaderMatch) {
      signals.push(
        contentSignal(
          'install-downloader-pattern',
          60,
          `Install-time downloader pattern found in tarball: ${entry.path}`,
          entry,
          'high',
          downloaderMatch
        )
      );
    }

    if (childProcessPattern.test(entry.sample) && networkExfilPattern.test(entry.sample)) {
      signals.push(
        contentSignal(
          'child-process-network-exfil',
          60,
          `child_process with network exfiltration pattern found in tarball: ${entry.path}`,
          entry,
          'high',
          'child_process plus network'
        )
      );
    }

    if (processEnvPattern.test(entry.sample) && networkExfilPattern.test(entry.sample)) {
      signals.push(
        contentSignal(
          'process-env-network-exfil',
          60,
          `process.env with network exfiltration pattern found in tarball: ${entry.path}`,
          entry,
          'high',
          'process.env plus network'
        )
      );
    }

    const obfuscationMatch = firstMatch(entry.sample, obfuscationPatterns);
    if (obfuscationMatch) {
      signals.push(
        contentSignal(
          'obfuscated-code-pattern',
          35,
          `Obfuscated JavaScript execution pattern found in tarball: ${entry.path}`,
          entry,
          'medium',
          obfuscationMatch
        )
      );
    }

    const walletMatch = firstMatch(entry.sample, walletHookPatterns);
    if (walletMatch) {
      signals.push(
        contentSignal(
          'wallet-transaction-hook',
          40,
          `Wallet transaction hook pattern found in tarball: ${entry.path}`,
          entry,
          'medium',
          walletMatch
        )
      );
    }
  }

  return { signals: [...signals, ...analyzeFrontendRuntimeEntries(entries)] };
}
