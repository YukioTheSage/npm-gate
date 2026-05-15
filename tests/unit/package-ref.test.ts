import { describe, expect, test } from 'vitest';
import { parsePackageRef } from '../../src/utils/package-ref.js';

describe('parsePackageRef', () => {
  test.each([
    ['lodash', { type: 'registry', sourceType: 'registry', name: 'lodash', range: undefined }],
    [
      'lodash@latest',
      { type: 'registry', sourceType: 'registry', name: 'lodash', range: 'latest' }
    ],
    [
      '@scope/pkg',
      { type: 'registry', sourceType: 'registry', name: '@scope/pkg', range: undefined }
    ],
    [
      '@scope/pkg@1.2.3',
      { type: 'registry', sourceType: 'registry', name: '@scope/pkg', range: '1.2.3' }
    ],
    [
      'file:../local',
      { type: 'local-directory', sourceType: 'local-directory', name: '../local', range: undefined }
    ],
    [
      'git+https://github.com/example/pkg.git',
      { type: 'git', sourceType: 'git', name: 'example/pkg', range: undefined }
    ],
    [
      'github:example/pkg',
      { type: 'git', sourceType: 'git', name: 'example/pkg', range: undefined }
    ],
    [
      './fixture.tgz',
      {
        type: 'local-tarball',
        sourceType: 'local-tarball',
        name: './fixture.tgz',
        range: undefined
      }
    ],
    [
      'file:./fixture.tgz',
      {
        type: 'local-tarball',
        sourceType: 'local-tarball',
        name: './fixture.tgz',
        range: undefined
      }
    ],
    [
      '../local-package',
      {
        type: 'local-directory',
        sourceType: 'local-directory',
        name: '../local-package',
        range: undefined
      }
    ],
    [
      'link:./linked-package',
      {
        type: 'local-directory',
        sourceType: 'local-directory',
        name: './linked-package',
        range: undefined
      }
    ],
    [
      'C:\\tmp\\fixture.tgz',
      {
        type: 'local-tarball',
        sourceType: 'local-tarball',
        name: 'C:\\tmp\\fixture.tgz',
        range: undefined
      }
    ],
    [
      'C:\\tmp\\local-package',
      {
        type: 'local-directory',
        sourceType: 'local-directory',
        name: 'C:\\tmp\\local-package',
        range: undefined
      }
    ],
    [
      'https://registry.example/pkg/-/pkg-1.0.0.tgz',
      {
        type: 'remote-tarball',
        sourceType: 'remote-tarball',
        name: 'https://registry.example/pkg/-/pkg-1.0.0.tgz',
        range: undefined
      }
    ],
    [
      'https://registry.example/pkg/-/pkg-1.0.0.tar.gz?cache=1',
      {
        type: 'remote-tarball',
        sourceType: 'remote-tarball',
        name: 'https://registry.example/pkg/-/pkg-1.0.0.tar.gz?cache=1',
        range: undefined
      }
    ],
    [
      'https://registry.example/pkg',
      {
        type: 'remote-tarball-unsupported',
        sourceType: 'remote-tarball-unsupported',
        name: 'https://registry.example/pkg',
        range: undefined
      }
    ]
  ])('parses %s', (input, expected) => {
    expect(parsePackageRef(input)).toMatchObject(expected);
  });
});
