import { request } from 'node:https';
import type {
  PackageManifest,
  RiskSignal,
  SourceVerificationRule,
  SourceVerifier
} from '../core/types.js';

interface SourceVerificationInput {
  packageName: string;
  version: string;
  currentManifest?: PackageManifest;
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

interface GitHubContentObject {
  type?: string;
  encoding?: string;
  content?: string;
}

const sourceManifestFields: Array<keyof PackageManifest> = [
  'scripts',
  'dependencies',
  'devDependencies',
  'peerDependencies',
  'optionalDependencies',
  'bundledDependencies',
  'bundleDependencies',
  'bin',
  'main',
  'exports',
  'files',
  'repository'
];

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
  required: boolean,
  matchedSignals = [id]
): RiskSignal {
  return {
    id,
    score: required ? 70 : 35,
    severity: required ? 'high' : 'medium',
    riskCategory: 'artifact_diff_risk',
    matchedSignals,
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

function manifestValue(manifest: PackageManifest, field: keyof PackageManifest): string {
  return JSON.stringify(manifest[field] ?? null);
}

async function sourceManifestSignals(input: {
  packageName: string;
  repository: string;
  ref: string | undefined;
  rule: SourceVerificationRule;
  verifier: SourceVerifier;
  currentManifest: PackageManifest | undefined;
  required: boolean;
}): Promise<RiskSignal[]> {
  if (!input.currentManifest || !input.ref || !input.verifier.fetchFile) return [];
  const currentManifest = input.currentManifest;
  const packageJsonPath = input.rule.packageJsonPath ?? 'package.json';
  const raw = await input.verifier.fetchFile(input.repository, input.ref, packageJsonPath);
  if (!raw) {
    return [
      sourceSignal(
        'source-manifest-unavailable',
        'Configured source package manifest was not found',
        {
          package: input.packageName,
          repository: input.repository,
          ref: input.ref,
          packageJsonPath
        },
        input.required
      )
    ];
  }

  let sourceManifest: PackageManifest;
  try {
    sourceManifest = JSON.parse(raw) as PackageManifest;
  } catch (error) {
    return [
      sourceSignal(
        'source-manifest-unavailable',
        'Configured source package manifest is not valid JSON',
        {
          package: input.packageName,
          repository: input.repository,
          ref: input.ref,
          packageJsonPath,
          error: error instanceof Error ? error.message : String(error)
        },
        input.required
      )
    ];
  }

  const mismatches = sourceManifestFields
    .filter((field) => manifestValue(sourceManifest, field) !== manifestValue(currentManifest, field))
    .map((field) => ({
      field,
      expected: sourceManifest[field],
      actual: currentManifest[field]
    }));

  if (mismatches.length === 0) return [];
  return [
    sourceSignal(
      'source-manifest-mismatch',
      'Published package manifest does not match configured source manifest',
      {
        package: input.packageName,
        repository: input.repository,
        ref: input.ref,
        packageJsonPath,
        mismatches
      },
      input.required,
      mismatches.map((mismatch) => mismatch.field)
    )
  ];
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

    const sourceRef = input.rule.commit ?? tagCommit ?? tag;
    return sourceManifestSignals({
      packageName: input.packageName,
      repository,
      ref: sourceRef,
      rule: input.rule,
      verifier: input.verifier,
      currentManifest: input.currentManifest,
      required
    });
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

  async fetchFile(repository: string, ref: string, path: string): Promise<string | undefined> {
    try {
      const encodedPath = path.split('/').map(encodeURIComponent).join('/');
      const file = await githubJson<GitHubContentObject>(
        `/repos/${repository}/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`
      );
      if (file.type !== 'file' || !file.content) return undefined;
      if (file.encoding === 'base64') {
        return Buffer.from(file.content.replace(/\s/g, ''), 'base64').toString('utf8');
      }
      return file.content;
    } catch {
      return undefined;
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
