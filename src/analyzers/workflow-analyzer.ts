import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import fg from 'fast-glob';
import { parse as parseYaml } from 'yaml';
import type { RiskSignal } from '../core/types.js';

export interface WorkflowAnalyzerOptions {
  requireWorkflowShaPinning: boolean;
  forbidReleaseCaches: boolean;
}

interface WorkflowStep {
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
}

interface WorkflowJob {
  permissions?: unknown;
  'runs-on'?: unknown;
  runsOn?: unknown;
  steps?: WorkflowStep[];
}

interface WorkflowFile {
  on?: unknown;
  true?: unknown;
  permissions?: unknown;
  jobs?: Record<string, WorkflowJob>;
}

const fullShaRef = /@[a-f0-9]{40}$/i;
const untrustedContext = /github\.event\.pull_request|github\.head_ref|github\.event\.workflow_run/;
const installOrBuildCommand = /\b(?:npm|pnpm|yarn)\s+(?:install|ci|test|run|build)\b/;
const riskyInstallCommand =
  /\b(?:npm|pnpm|yarn)\s+(?:install|ci)\b(?![^\n]*(?:--ignore-scripts|--ignore-scripts=true))/;
const publishCommand = /\b(?:npm|pnpm)\s+publish\b/;
const writePermissions = new Set(['write', 'all']);
const broadPermissionKeys = new Set(['contents', 'packages', 'actions', 'id-token']);

function workflowSignal(
  id: string,
  message: string,
  file: string,
  value?: unknown,
  score = 70,
  severity: RiskSignal['severity'] = 'high'
): RiskSignal {
  return {
    id,
    score,
    severity,
    riskCategory: 'ci_trust_boundary_risk',
    matchedSignals: [id],
    message,
    evidence: [
      {
        type: 'file',
        message: file,
        value: { file, ...(value && typeof value === 'object' ? value : { value }) }
      }
    ],
    remediation: [
      'Split untrusted pull request work from privileged release work.',
      'Pin actions to full commit SHAs and remove caches from release or privileged jobs.'
    ],
    canOverride: false
  };
}

function asArray<T>(value: T | T[] | undefined): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function eventNames(onValue: unknown, raw: string): Set<string> {
  const events = new Set<string>();
  const value = onValue;
  if (typeof value === 'string') events.add(value);
  if (Array.isArray(value)) {
    for (const entry of value) if (typeof entry === 'string') events.add(entry);
  }
  if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) events.add(key);
  }
  if (/^\s*on:\s*pull_request_target\s*$/m.test(raw)) events.add('pull_request_target');
  if (/^\s*on:\s*workflow_run\s*$/m.test(raw)) events.add('workflow_run');
  return events;
}

function isDangerousTrigger(events: Set<string>): boolean {
  return events.has('pull_request_target') || events.has('workflow_run');
}

function hasUntrustedCheckout(steps: WorkflowStep[]): boolean {
  return steps.some(
    (step) =>
      typeof step.uses === 'string' &&
      step.uses.startsWith('actions/checkout') &&
      JSON.stringify(step.with ?? {}).match(untrustedContext)
  );
}

function usesCache(steps: WorkflowStep[]): boolean {
  return steps.some((step) => {
    if (typeof step.uses === 'string' && /^actions\/cache@/i.test(step.uses)) return true;
    if (
      typeof step.uses === 'string' &&
      /^actions\/setup-node@/i.test(step.uses) &&
      Object.prototype.hasOwnProperty.call(step.with ?? {}, 'cache')
    ) {
      return true;
    }
    return false;
  });
}

function downloadsArtifact(steps: WorkflowStep[]): boolean {
  return steps.some(
    (step) =>
      (typeof step.uses === 'string' && /^actions\/download-artifact@/i.test(step.uses)) ||
      (typeof step.run === 'string' && /\bdownload-artifact\b/i.test(step.run))
  );
}

function executesPackageManager(steps: WorkflowStep[]): boolean {
  return steps.some((step) => typeof step.run === 'string' && installOrBuildCommand.test(step.run));
}

function hasRiskyInstall(steps: WorkflowStep[]): boolean {
  return steps.some((step) => typeof step.run === 'string' && riskyInstallCommand.test(step.run));
}

function publishesPackage(steps: WorkflowStep[]): boolean {
  return steps.some((step) => typeof step.run === 'string' && publishCommand.test(step.run));
}

function hasIdTokenWrite(workflowPermissions: unknown, jobPermissions: unknown): boolean {
  return broadPermissions(workflowPermissions, jobPermissions).includes('id-token: write');
}

function isSelfHostedRunner(job: WorkflowJob): boolean {
  const value = job['runs-on'] ?? job.runsOn;
  if (typeof value === 'string') return value.includes('self-hosted');
  if (Array.isArray(value)) return value.some((entry) => String(entry).includes('self-hosted'));
  return false;
}

function unpinnedActions(steps: WorkflowStep[]): string[] {
  return steps
    .map((step) => step.uses)
    .filter((uses): uses is string => Boolean(uses))
    .filter((uses) => !uses.startsWith('./') && !uses.startsWith('docker://'))
    .filter((uses) => !fullShaRef.test(uses));
}

function broadPermissions(workflowPermissions: unknown, jobPermissions: unknown): string[] {
  const permissions = [workflowPermissions, jobPermissions];
  const broad: string[] = [];
  for (const permission of permissions) {
    if (permission === 'write-all') broad.push('write-all');
    if (!permission || typeof permission !== 'object') continue;
    for (const [key, value] of Object.entries(permission)) {
      if (
        broadPermissionKeys.has(key) &&
        typeof value === 'string' &&
        writePermissions.has(value)
      ) {
        broad.push(`${key}: ${value}`);
      }
    }
  }
  return [...new Set(broad)];
}

async function analyzeWorkflowFile(
  cwd: string,
  file: string,
  options: WorkflowAnalyzerOptions
): Promise<RiskSignal[]> {
  const absolute = join(cwd, file);
  const raw = await readFile(absolute, 'utf8');
  const parsed = (parseYaml(raw) ?? {}) as WorkflowFile;
  const onValue = parsed.on ?? parsed.true;
  const events = eventNames(onValue, raw);
  const dangerousTrigger = isDangerousTrigger(events);
  const signals: RiskSignal[] = [];
  const jobs = Object.entries(parsed.jobs ?? {});

  for (const [jobName, job] of jobs) {
    const steps = asArray(job.steps);
    if (dangerousTrigger && (hasUntrustedCheckout(steps) || executesPackageManager(steps))) {
      signals.push(
        workflowSignal(
          'workflow-dangerous-trigger',
          'Workflow uses a privileged trigger with untrusted work',
          file,
          {
            job: jobName,
            events: [...events]
          }
        )
      );
    }
    if (dangerousTrigger && hasUntrustedCheckout(steps)) {
      signals.push(
        workflowSignal(
          'workflow-untrusted-checkout',
          'Privileged workflow checks out untrusted pull request code',
          file,
          {
            job: jobName
          }
        )
      );
    }
    if ((dangerousTrigger || options.forbidReleaseCaches) && usesCache(steps)) {
      signals.push(
        workflowSignal(
          'workflow-cache-poisoning-risk',
          'Workflow cache can cross a privileged trust boundary',
          file,
          {
            job: jobName
          }
        )
      );
    }
    if (events.has('workflow_run') && downloadsArtifact(steps)) {
      signals.push(
        workflowSignal(
          'workflow-run-artifact-trust-boundary',
          'workflow_run job consumes artifacts across a trust boundary',
          file,
          { job: jobName, events: [...events] }
        )
      );
    }
    if (hasIdTokenWrite(parsed.permissions, job.permissions) && usesCache(steps)) {
      signals.push(
        workflowSignal(
          'workflow-oidc-cache-boundary',
          'OIDC token minting is combined with package-manager cache restore',
          file,
          { job: jobName }
        )
      );
    }
    if (dangerousTrigger && isSelfHostedRunner(job)) {
      signals.push(
        workflowSignal(
          'workflow-self-hosted-untrusted-runner',
          'Untrusted workflow context can run on a self-hosted runner',
          file,
          { job: jobName }
        )
      );
    }
    if (publishesPackage(steps) && hasRiskyInstall(steps)) {
      signals.push(
        workflowSignal(
          'workflow-publish-after-risky-install',
          'Workflow publishes after package installation with lifecycle scripts enabled',
          file,
          { job: jobName }
        )
      );
    }
    const broad = broadPermissions(parsed.permissions, job.permissions);
    if (dangerousTrigger && broad.length > 0) {
      signals.push(
        workflowSignal(
          'workflow-overprivileged-token',
          'Privileged workflow grants broad token permissions',
          file,
          {
            job: jobName,
            permissions: broad
          }
        )
      );
    }
    if (options.requireWorkflowShaPinning) {
      const actions = unpinnedActions(steps);
      if (actions.length > 0) {
        signals.push(
          workflowSignal(
            'workflow-unpinned-action',
            'Workflow uses an action that is not pinned to a full commit SHA',
            file,
            { job: jobName, actions },
            35,
            'medium'
          )
        );
      }
    }
  }

  return signals;
}

export async function analyzeGitHubWorkflows(
  cwd: string,
  options: WorkflowAnalyzerOptions
): Promise<RiskSignal[]> {
  const files = await fg('.github/workflows/*.{yml,yaml}', {
    cwd,
    onlyFiles: true,
    dot: true
  });
  const results = await Promise.all(files.map((file) => analyzeWorkflowFile(cwd, file, options)));
  return results.flat();
}
