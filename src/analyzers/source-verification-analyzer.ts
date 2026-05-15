import { request } from 'node:https';
import type { RiskSignal, SourceVerificationRule, SourceVerifier } from '../core/types.js';

interface SourceVerificationInput {
  packageName: string;
  version: string;
  rule: SourceVerificationRule;
  verifier: SourceVerifier;
}

interface GitHubApiObject {
  object?: {
    type?: string;
    sha?: string;
  };
}

interface GitHubTagObject {
  object?: {
    type?: string;
    sha?: string;
  };
}

export function normalizeGitHubRepository(repository: string): string | undefined {
  const trimmed = repository.trim().replace(/\.git$/, '');
  const direct = trimmed.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  if (direct) return `${direct[1]}/${direct[2]}`;
  try {
    const url = new URL(trimmed);
    if (url.hostname !== 'github.com') return undefined;
    const [owner, repo] = url.pathname.replace(/^\/|\/$/g, '').split('/');
    return owner && repo ? `${owner}/${repo.replace(/\.git$/, '')}` : undefined;
  } catch {
    return undefined;
  }
}

function sourceSignal(
  id: string,
  message: string,
  value: unknown,
  required: boolean
): RiskSignal {
  return {
    id,
    score: required ? 70 : 35,
    severity: required ? 'high' : 'medium',
    riskCategory: 'artifact_diff_risk',
    matchedSignals: [id],
    manualReview: !required,
    message,
    evidence: [{ type: 'source-verification', message, value }],
    remediation: [
      required
        ? 'Do not install until the configured source tag or commit can be verified.'
        : 'Review source repository metadata before installing.'
    ],
    canOverride: !required
  };
}

function tagFromTemplate(template: string | undefined, version: string): string | undefined {
  return template?.replaceAll('{version}', version);
}

export async function sourceVerificationSignals(
  input: SourceVerificationInput
): Promise<RiskSignal[]> {
  const repository = normalizeGitHubRepository(input.rule.repository);
  const required = input.rule.required === true;
  if (!repository) {
    return [
      sourceSignal(
        'source-verification-unavailable',
        'Configured source repository is not a supported GitHub repository',
        { package: input.packageName, repository: input.rule.repository },
        required
      )
    ];
  }

  try {
    const tag = tagFromTemplate(input.rule.tagTemplate, input.version);
    const tagCommit = tag ? await input.verifier.resolveTagCommit(repository, tag) : undefined;
    if (tag && !tagCommit) {
      return [
        sourceSignal(
          'source-tag-missing',
          'Configured source tag was not found',
          { package: input.packageName, repository, tag },
          required
        )
      ];
    }

    if (input.rule.commit) {
      const commitExists = await input.verifier.hasCommit(repository, input.rule.commit);
      if (!commitExists) {
        return [
          sourceSignal(
            'source-commit-missing',
            'Configured source commit was not found',
            { package: input.packageName, repository, commit: input.rule.commit },
            required
          )
        ];
      }
      if (tagCommit && tagCommit !== input.rule.commit) {
        return [
          sourceSignal(
            'source-tag-commit-mismatch',
            'Configured source tag does not resolve to the expected commit',
            {
              package: input.packageName,
              repository,
              tag,
              expectedCommit: input.rule.commit,
              actualCommit: tagCommit
            },
            required
          )
        ];
      }
    }

    return [];
  } catch (error) {
    return [
      sourceSignal(
        'source-verification-unavailable',
        'Unable to verify configured source repository metadata',
        {
          package: input.packageName,
          repository,
          error: error instanceof Error ? error.message : String(error)
        },
        required
      )
    ];
  }
}

export class GitHubSourceVerifier implements SourceVerifier {
  async resolveTagCommit(repository: string, tag: string): Promise<string | undefined> {
    const ref = await githubJson<GitHubApiObject>(`/repos/${repository}/git/ref/tags/${tag}`);
    const object = ref.object;
    if (!object?.sha) return undefined;
    if (object.type === 'commit') return object.sha;
    if (object.type !== 'tag') return undefined;
    const tagObject = await githubJson<GitHubTagObject>(`/repos/${repository}/git/tags/${object.sha}`);
    return tagObject.object?.type === 'commit' ? tagObject.object.sha : undefined;
  }

  async hasCommit(repository: string, commit: string): Promise<boolean> {
    try {
      await githubJson<unknown>(`/repos/${repository}/commits/${commit}`);
      return true;
    } catch {
      return false;
    }
  }
}

function githubJson<T>(path: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        hostname: 'api.github.com',
        path,
        method: 'GET',
        headers: {
          accept: 'application/vnd.github+json',
          'user-agent': 'npm-gate-source-verifier'
        }
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if ((res.statusCode ?? 500) >= 400) {
            reject(new Error(`GitHub API returned ${res.statusCode ?? 'unknown'}`));
            return;
          }
          try {
            resolve(JSON.parse(body) as T);
          } catch (error) {
            reject(error);
          }
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}
