import type { Command } from 'commander';

interface Explanation {
  title: string;
  meaning: string;
  remediation: string[];
}

const explanations: Record<string, Explanation> = {
  'registry-tarball-uninspectable': {
    title: 'Registry tarball could not be inspected',
    meaning: 'npm-gate could not safely fetch, unpack, or read the package tarball manifest.',
    remediation: [
      'Do not install or release with this dependency until inspection succeeds.',
      'Retry against a trusted registry or pin a known-good version.',
      'If the package was already installed, rotate reachable tokens and review CI logs.'
    ]
  },
  'registry-tarball-integrity-mismatch': {
    title: 'Registry tarball integrity mismatch',
    meaning: 'The fetched tarball bytes do not match the integrity value advertised by metadata.',
    remediation: [
      'Do not install or release with this dependency.',
      'Refresh the lockfile from a trusted registry.',
      'Rotate reachable tokens if this package was already installed on a sensitive host.'
    ]
  },
  'workflow-cache-poisoning-risk': {
    title: 'Workflow cache poisoning risk',
    meaning:
      'A workflow cache can cross a privileged trust boundary and affect release or privileged jobs.',
    remediation: [
      'Do not install or release from this workflow until cache use is removed or isolated.',
      'Split untrusted PR work from privileged release work.',
      'If already run, rotate reachable tokens and review workflow logs.'
    ]
  },
  'workflow-dangerous-trigger': {
    title: 'Dangerous privileged workflow trigger',
    meaning:
      'A privileged trigger such as pull_request_target or workflow_run is combined with untrusted work.',
    remediation: [
      'Do not install or release from this workflow.',
      'Move untrusted code execution to pull_request with read-only permissions.',
      'Use a separate privileged follow-up workflow only for reviewed artifacts.'
    ]
  },
  'workflow-untrusted-checkout': {
    title: 'Privileged workflow checks out untrusted code',
    meaning: 'The workflow can run fork-controlled code in a privileged context.',
    remediation: [
      'Do not install or release from this workflow.',
      'Remove untrusted checkout from privileged jobs.',
      'Rotate reachable tokens if the workflow has already run with secrets or write permissions.'
    ]
  },
  'workflow-overprivileged-token': {
    title: 'Overprivileged workflow token',
    meaning:
      'The workflow grants broad token permissions in a context that can be influenced by untrusted input.',
    remediation: [
      'Reduce permissions to least privilege.',
      'Avoid id-token: write unless the job is a protected release job.',
      'Rotate reachable tokens and audit cloud/npm/GitHub logs after suspected exposure.'
    ]
  },
  'unapproved-resolved-host': {
    title: 'Lockfile resolves from an unapproved host',
    meaning: 'A lockfile entry points at a tarball host outside the approved registry set.',
    remediation: [
      'Do not install with this lockfile.',
      'Regenerate the lockfile from a trusted registry.',
      'Review for dependency confusion or registry substitution.'
    ]
  },
  'lockfile-integrity-changed': {
    title: 'Lockfile integrity changed without version change',
    meaning:
      'The same package version now has different integrity bytes, which can indicate tampering.',
    remediation: [
      'Do not install with this lockfile.',
      'Regenerate from a trusted registry and compare the diff.',
      'Pin a known-good version and review the package tarball.'
    ]
  },
  'required-intelligence-unavailable': {
    title: 'Required intelligence source unavailable',
    meaning: 'A policy-required advisory source could not be queried.',
    remediation: [
      'Do not install or release until the intelligence source is restored.',
      'Use an approved offline advisory snapshot if available.',
      'Avoid overriding this in CI.'
    ]
  }
};

export function explainFindingId(findingId: string): string {
  const signalId = findingId.split(':')[0] ?? findingId;
  const explanation = explanations[signalId] ?? {
    title: 'npm-gate finding',
    meaning: 'This finding was produced by npm-gate policy analysis.',
    remediation: [
      'Do not install or release until the finding is reviewed.',
      'For block findings, rotate reachable tokens if the package or workflow already ran.'
    ]
  };
  return [
    `${signalId}: ${explanation.title}`,
    '',
    explanation.meaning,
    '',
    'Recommended response:',
    ...explanation.remediation.map((item) => `- ${item}`)
  ].join('\n');
}

export function registerExplainCommand(program: Command): void {
  program
    .command('explain <finding-id>')
    .description('Explain a finding id and show acceptable remediation')
    .action(async (findingId: string) => {
      process.stdout.write(`${explainFindingId(findingId)}\n`);
      process.exitCode = 0;
    });
}
