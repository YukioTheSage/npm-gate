# Release Hardening

Before publishing npm-gate, verify that runtime dependencies have an exact published dependency tree:

```sh
pnpm run release:verify-deps
```

The release check requires `npm-shrinkwrap.json` when runtime dependencies exist. npm publishes shrinkwrap files with packages and uses them to define the install tree for consumers.

Refresh `npm-shrinkwrap.json` only in a reviewed release workflow with lifecycle scripts disabled. Do not use dependency refreshes as part of unrelated feature work, and review any shrinkwrap diff as release-critical supply-chain metadata.

The pack smoke runs the same verification before `pnpm pack`, so release artifacts fail early if the exact dependency strategy is missing.
