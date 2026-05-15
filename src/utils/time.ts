export function nowIso(now = new Date()): string {
  return now.toISOString();
}

export function hoursBetween(from: Date, to: Date): number {
  return Math.max(0, (to.getTime() - from.getTime()) / 3_600_000);
}

export function isExpired(expiresAt: string | undefined, now = new Date()): boolean {
  return Boolean(expiresAt && new Date(expiresAt).getTime() <= now.getTime());
}
