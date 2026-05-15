# Examples

## Dry Run an Install

```sh
npm-gate install axios --dry-run
```

## Inspect a Local Tarball Before Install

```sh
npm-gate install ./pkg.tgz --dry-run --json
```

## Inspect a Configured-Registry Tarball Before Install

```sh
npm-gate install https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz --dry-run --json
```

Remote tarballs from arbitrary hosts are blocked. Configure the npm registry before using a private registry tarball URL.

## Inspect a Local Directory Before Install

```sh
npm-gate install file:./pkg --dry-run
```

Warnings install in local mode unless `--strict` is set. Blocked direct sources never delegate to npm.

## Gate a Direct Git Source

```sh
npm-gate install github:user/repo --dry-run --json
```

Direct Git sources are not cloned. They warn locally and block in strict, block, or CI modes.

## Strict CI Gate

```sh
NPM_GATE_MODE=ci npm-gate ci --json
```

## Add an Allowlist Entry

```sh
npm-gate allow lodash@^4.17.21 --reason "Approved base dependency SEC-42"
```

## Explain a Package

```sh
npm-gate policy explain react@18.3.1
```

## Explain a Finding

```sh
npm-gate explain workflow-cache-poisoning-risk:.github/workflows/release.yml
```

## Generate a Report

```sh
npm-gate report --format json > npm-gate-report.json
```
