import type { RiskSignal, TarballEntry } from '../core/types.js';

const patterns: Array<{
  id: string;
  label: string;
  pattern: RegExp;
  severity: RiskSignal['severity'];
  score: number;
}> = [
  {
    id: 'frontend-runtime-wallet-access',
    label: 'wallet provider access',
    pattern: /(?:window\.)?(?:ethereum|solana)\.(?:request|send|sendTransaction)|eth_sendTransaction|walletconnect/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'frontend-runtime-clipboard-mutation',
    label: 'clipboard mutation',
    pattern: /navigator\.clipboard\.writeText|document\.execCommand\(['"]copy/i,
    severity: 'high',
    score: 55
  },
  {
    id: 'frontend-runtime-transaction-mutation',
    label: 'transaction object mutation',
    pattern: /\b(?:tx|transaction)\.(?:to|from|value|data)\s*=/i,
    severity: 'high',
    score: 60
  },
  {
    id: 'frontend-runtime-fetch-interception',
    label: 'fetch interception',
    pattern: /(?:window\.)?fetch\s*=\s*(?:new\s+Proxy|function|\()/i,
    severity: 'medium',
    score: 35
  },
  {
    id: 'frontend-runtime-xhr-interception',
    label: 'XMLHttpRequest interception',
    pattern: /XMLHttpRequest\.prototype\.(?:open|send)\s*=/i,
    severity: 'medium',
    score: 35
  },
  {
    id: 'frontend-runtime-websocket-interception',
    label: 'WebSocket interception',
    pattern: /WebSocket\.prototype\.(?:send|addEventListener)\s*=/i,
    severity: 'medium',
    score: 35
  },
  {
    id: 'frontend-runtime-cdn-latest',
    label: 'CDN latest usage',
    pattern: /https?:\/\/[^'"]+@latest\b/i,
    severity: 'medium',
    score: 30
  },
  {
    id: 'frontend-runtime-missing-sri',
    label: 'external script without SRI',
    pattern: /<script\b(?=[^>]*\bsrc=["']https?:\/\/)(?![^>]*\bintegrity=)[^>]*>/i,
    severity: 'medium',
    score: 30
  },
  {
    id: 'frontend-runtime-obfuscated-payload',
    label: 'obfuscated browser payload',
    pattern: /\b(?:eval\s*\(|new\s+Function|Function\s*\(|atob\s*\(|Buffer\.from\s*\([\s\S]{0,160}base64)/i,
    severity: 'medium',
    score: 35
  }
];

export function analyzeFrontendRuntimeEntries(entries: TarballEntry[]): RiskSignal[] {
  const signals: RiskSignal[] = [];
  for (const entry of entries) {
    const content = entry.fullText ?? entry.sample;
    if (!content) continue;
    for (const rule of patterns) {
      if (!rule.pattern.test(content)) continue;
      signals.push({
        id: rule.id,
        score: rule.score,
        severity: rule.severity,
        riskCategory: 'frontend_runtime_risk',
        matchedSignals: [rule.label],
        message: `Browser runtime risk detected: ${rule.label}`,
        evidence: [
          {
            type: 'tarball-entry',
            message: `${entry.path} matches ${rule.label}`,
            value: { path: entry.path, size: entry.size, risk: 'runtime-browser' }
          }
        ],
        remediation: ['Review browser-bundled code before shipping this dependency update.'],
        canOverride: true,
        manualReview: true
      });
    }
  }
  return signals;
}
