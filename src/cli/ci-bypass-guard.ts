const truthy = new Set(['1', 'true', 'yes']);

function isTruthy(value: string | undefined): boolean {
  return value ? truthy.has(value.toLowerCase()) : false;
}

export function isCiOrReleaseEnv(
  env: NodeJS.ProcessEnv | Record<string, string | undefined>
): boolean {
  return (
    isTruthy(env.CI) ||
    isTruthy(env.GITHUB_ACTIONS) ||
    isTruthy(env.NPM_GATE_RELEASE) ||
    isTruthy(env.RELEASE) ||
    isTruthy(env.CI_RELEASE)
  );
}

export function assertModeOffAllowed(
  env: NodeJS.ProcessEnv | Record<string, string | undefined>
): void {
  if (env.NPM_GATE_MODE === 'off' && isCiOrReleaseEnv(env)) {
    throw new Error(
      'NPM_GATE_MODE=off is forbidden in CI or release contexts. Remove the bypass or run outside CI.'
    );
  }
}
