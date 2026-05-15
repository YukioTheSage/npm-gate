# Contributing

## Development Setup

```sh
pnpm install
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

Use Node.js 20.17.0 or newer. Keep dependencies small, auditable, and directly relevant to npm package analysis.

## Contribution Standards

- Keep the project defensive-only.
- Do not add exploit payloads, credential collection, malware, or live attack simulation.
- Use synthetic inert fixtures for all malicious-package examples.
- Add or update tests for analyzer, policy, reporting, and CLI behavior changes.
- Do not log tokens or secrets.
- Prefer deterministic heuristics over network-heavy behavior.

## Pull Requests

Pull requests should describe the risk model change, affected commands, test coverage, and any new limitations. Security-sensitive changes should mention how token redaction and no-execution guarantees are preserved.
