export interface NameConfusionFinding {
  protectedName: string;
  confidence: 'low' | 'medium' | 'high';
  explanation: string;
  distance: number;
}

function normalize(name: string): string {
  return name
    .replace(/^@/, '')
    .replace(/\//g, '-')
    .replace(/[_\-.]/g, '')
    .toLowerCase();
}

function tokens(name: string): string[] {
  return name
    .replace(/^@/, '')
    .split(/[/_.-]+/)
    .map((token) => token.toLowerCase())
    .filter(Boolean);
}

function scopeAlias(name: string): string | undefined {
  const match = name.match(/^@([^/]+)\/(.+)$/);
  return match ? `${match[1]}-${match[2]}` : undefined;
}

export function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, () => Array<number>(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) dp[i]![0] = i;
  for (let j = 0; j <= b.length; j += 1) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      dp[i]![j] = Math.min(
        dp[i - 1]![j]! + 1,
        dp[i]![j - 1]! + 1,
        dp[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length]![b.length]!;
}

export function detectNameConfusion(
  packageName: string,
  protectedPackageNames: string[]
): NameConfusionFinding | undefined {
  for (const protectedName of protectedPackageNames) {
    if (packageName === protectedName) continue;
    const normalizedCandidate = normalize(packageName);
    const normalizedProtected = normalize(protectedName);
    const alias = scopeAlias(protectedName);
    const aliasNormalized = alias ? normalize(alias) : undefined;
    const distance = levenshtein(normalizedCandidate, normalizedProtected);
    const candidateTokens = tokens(packageName);
    const protectedTokens = tokens(protectedName);
    const sortedCandidate = [...candidateTokens].sort().join('-');
    const sortedProtected = [...protectedTokens].sort().join('-');

    if (normalizedCandidate === normalizedProtected || normalizedCandidate === aliasNormalized) {
      return {
        protectedName,
        confidence: 'high',
        distance: 0,
        explanation: `${packageName} is similar to protected package ${protectedName} after separator or scope normalization`
      };
    }

    if (normalizedProtected.length >= 5 && distance <= 2) {
      return {
        protectedName,
        confidence: distance <= 1 ? 'high' : 'medium',
        distance,
        explanation: `${packageName} is similar to protected package ${protectedName} with edit distance ${distance}`
      };
    }

    if (
      protectedTokens.length > 1 &&
      candidateTokens.length === protectedTokens.length &&
      sortedCandidate === sortedProtected
    ) {
      return {
        protectedName,
        confidence: 'medium',
        distance,
        explanation: `${packageName} reorders tokens from protected package ${protectedName}`
      };
    }

    if (
      normalizedProtected.length >= 5 &&
      normalizedCandidate.startsWith(normalizedProtected) &&
      normalizedCandidate.length > normalizedProtected.length
    ) {
      return {
        protectedName,
        confidence: 'medium',
        distance,
        explanation: `${packageName} adds a suffix to protected package ${protectedName}`
      };
    }

    if (
      normalizedProtected.length >= 5 &&
      normalizedCandidate.endsWith(normalizedProtected) &&
      normalizedCandidate.length > normalizedProtected.length
    ) {
      return {
        protectedName,
        confidence: 'medium',
        distance,
        explanation: `${packageName} adds a prefix to protected package ${protectedName}`
      };
    }
  }

  return undefined;
}
