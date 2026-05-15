import { isAbsolute, win32 } from 'node:path';

import type { PackageSourceType } from '../core/types.js';

export type ParsedPackageRef =
  | {
      raw: string;
      type: 'registry';
      sourceType: Extract<PackageSourceType, 'registry'>;
      name: string;
      range?: string;
    }
  | {
      raw: string;
      type: 'local-tarball';
      sourceType: Extract<PackageSourceType, 'local-tarball'>;
      name: string;
      spec: string;
      range?: undefined;
    }
  | {
      raw: string;
      type: 'local-directory';
      sourceType: Extract<PackageSourceType, 'local-directory'>;
      name: string;
      spec: string;
      range?: undefined;
    }
  | {
      raw: string;
      type: 'remote-tarball-unsupported';
      sourceType: Extract<PackageSourceType, 'remote-tarball-unsupported'>;
      name: string;
      spec: string;
      range?: undefined;
    }
  | {
      raw: string;
      type: 'remote-tarball';
      sourceType: Extract<PackageSourceType, 'remote-tarball'>;
      name: string;
      spec: string;
      range?: undefined;
    }
  | {
      raw: string;
      type: 'git';
      sourceType: Extract<PackageSourceType, 'git'>;
      name: string;
      spec: string;
      range?: undefined;
    };

const gitPrefixes = ['git+', 'git://', 'github:', 'gitlab:', 'bitbucket:', 'ssh://git@'];
const localPrefixes = ['file:', 'link:'];

function stripLocalPrefix(spec: string): string {
  return spec.replace(/^(file:|link:)/, '');
}

function looksLikeLocalPath(spec: string): boolean {
  const path = stripLocalPrefix(spec);
  return (
    spec.startsWith('file:') ||
    spec.startsWith('link:') ||
    path.startsWith('./') ||
    path.startsWith('../') ||
    path.startsWith('.\\') ||
    path.startsWith('..\\') ||
    path === '.' ||
    path === '..' ||
    isAbsolute(path) ||
    win32.isAbsolute(path)
  );
}

function looksLikeTarballPath(spec: string): boolean {
  const path = stripLocalPrefix(spec).toLowerCase();
  return path.endsWith('.tgz') || path.endsWith('.tar.gz');
}

function localNameFromSpec(spec: string): string {
  return stripLocalPrefix(spec);
}

function gitNameFromSpec(spec: string): string {
  const githubLike = spec.match(/^(?:github:|gitlab:|bitbucket:)([^#]+)(?:#.+)?$/);
  if (githubLike) return githubLike[1] ?? spec;

  const path = spec.replace(/^git\+/, '').replace(/#.+$/, '');
  const parts = path.split('/');
  const repo = parts.at(-1)?.replace(/\.git$/, '') ?? path;
  const owner = parts.at(-2);
  return owner ? `${owner}/${repo}` : repo;
}

export function parsePackageRef(raw: string): ParsedPackageRef {
  if (/^https?:\/\/.+\.(?:tgz|tar\.gz)(?:[?#].*)?$/i.test(raw)) {
    return {
      raw,
      type: 'remote-tarball',
      sourceType: 'remote-tarball',
      name: raw,
      spec: raw,
      range: undefined
    };
  }

  if (/^https?:\/\//i.test(raw) && !/^https:\/\/github\.com\//.test(raw)) {
    return {
      raw,
      type: 'remote-tarball-unsupported',
      sourceType: 'remote-tarball-unsupported',
      name: raw,
      spec: raw,
      range: undefined
    };
  }

  if (
    gitPrefixes.some((prefix) => raw.startsWith(prefix)) ||
    /^https:\/\/github\.com\//.test(raw)
  ) {
    return {
      raw,
      type: 'git',
      sourceType: 'git',
      name: gitNameFromSpec(raw),
      spec: raw,
      range: undefined
    };
  }

  if (localPrefixes.some((prefix) => raw.startsWith(prefix)) || looksLikeLocalPath(raw)) {
    if (looksLikeTarballPath(raw)) {
      return {
        raw,
        type: 'local-tarball',
        sourceType: 'local-tarball',
        name: localNameFromSpec(raw),
        spec: stripLocalPrefix(raw),
        range: undefined
      };
    }
    return {
      raw,
      type: 'local-directory',
      sourceType: 'local-directory',
      name: localNameFromSpec(raw),
      spec: stripLocalPrefix(raw),
      range: undefined
    };
  }

  if (raw.startsWith('@')) {
    const slash = raw.indexOf('/');
    const versionAt = slash === -1 ? -1 : raw.indexOf('@', slash);
    if (versionAt !== -1) {
      return {
        raw,
        type: 'registry',
        sourceType: 'registry',
        name: raw.slice(0, versionAt),
        range: raw.slice(versionAt + 1) || undefined
      };
    }
    return { raw, type: 'registry', sourceType: 'registry', name: raw, range: undefined };
  }

  const versionAt = raw.lastIndexOf('@');
  if (versionAt > 0) {
    return {
      raw,
      type: 'registry',
      sourceType: 'registry',
      name: raw.slice(0, versionAt),
      range: raw.slice(versionAt + 1) || undefined
    };
  }

  return { raw, type: 'registry', sourceType: 'registry', name: raw, range: undefined };
}

export function isGitSpec(spec: string | undefined): boolean {
  return Boolean(spec && parsePackageRef(spec).type === 'git');
}
