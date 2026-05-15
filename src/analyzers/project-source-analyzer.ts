import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import fg from 'fast-glob';
import type { RiskSignal } from '../core/types.js';

const sourcePatterns = ['**/*.{html,htm,js,mjs,cjs,ts,tsx,jsx,vue,svelte,astro,mdx}'];
const ignoredPaths = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/.pnpm-store/**',
  '**/.npm/**',
  '**/.yarn/**',
  '**/.turbo/**',
  '**/.next/**',
  '**/out/**'
];

const scriptTagPattern = /<script\b(?=[^>]*\bsrc=["']https?:\/\/)[^>]*>/gi;
const latestUrlPattern = /https?:\/\/[^'"\s<>]+@latest\b[^'"\s<>]*/gi;

function projectRuntimeSignal(input: {
  id: 'project-cdn-latest' | 'project-external-script-missing-sri';
  file: string;
  message: string;
  value: unknown;
  score: number;
  severity: RiskSignal['severity'];
}): RiskSignal {
  return {
    id: input.id,
    score: input.score,
    severity: input.severity,
    riskCategory: 'frontend_runtime_risk',
    matchedSignals: [input.id],
    manualReview: true,
    message: input.message,
    evidence: [
      {
        type: 'file',
        message: input.file,
        value: { file: input.file, value: input.value }
      }
    ],
    remediation: [
      'Pin external browser dependencies to exact versions and require Subresource Integrity.'
    ],
    canOverride: true
  };
}

function hasIntegrity(scriptTag: string): boolean {
  return /\bintegrity\s*=/i.test(scriptTag);
}

export async function analyzeProjectRuntimeSources(cwd: string): Promise<RiskSignal[]> {
  const files = await fg(sourcePatterns, {
    cwd,
    onlyFiles: true,
    dot: false,
    ignore: ignoredPaths
  });
  const signals: RiskSignal[] = [];

  for (const file of files) {
    const source = await readFile(join(cwd, file), 'utf8');
    const latestUrlsAlreadyReported = new Set<string>();

    for (const match of source.matchAll(scriptTagPattern)) {
      const scriptTag = match[0];
      const latestUrl = scriptTag.match(latestUrlPattern)?.[0];
      if (latestUrl) {
        latestUrlsAlreadyReported.add(latestUrl);
        signals.push(
          projectRuntimeSignal({
            id: 'project-cdn-latest',
            file,
            message: 'Project source references a CDN latest URL',
            value: { scriptTag, url: latestUrl },
            score: 45,
            severity: 'high'
          })
        );
        continue;
      }

      if (!hasIntegrity(scriptTag)) {
        signals.push(
          projectRuntimeSignal({
            id: 'project-external-script-missing-sri',
            file,
            message: 'Project source references an external script without SRI',
            value: { scriptTag },
            score: 30,
            severity: 'medium'
          })
        );
      }
    }

    for (const match of source.matchAll(latestUrlPattern)) {
      const url = match[0];
      if (latestUrlsAlreadyReported.has(url)) continue;
      signals.push(
        projectRuntimeSignal({
          id: 'project-cdn-latest',
          file,
          message: 'Project source references a CDN latest URL',
          value: { url },
          score: 45,
          severity: 'high'
        })
      );
    }
  }

  return signals;
}
