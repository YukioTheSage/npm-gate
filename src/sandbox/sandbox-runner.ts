import type { SandboxPlan } from './sandbox-plan.js';

export function renderSandboxPlan(plan: SandboxPlan): string {
  return `${JSON.stringify(plan, null, 2)}\n`;
}

export async function runSandboxPlan(plan: SandboxPlan): Promise<SandboxPlan> {
  return plan;
}
