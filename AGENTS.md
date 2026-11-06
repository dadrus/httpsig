# AGENTS.md

This file provides repository-specific guidance for AI coding agents working on httpsig.

## Project context

`httpsig` implements HTTP Message Signatures (RFC 9421) and uses HTTP Structured Fields (RFC 8941, via `httpsfv`).

## Scope and design

- `httpsig` implements security related code. **Every change must be reviewed for security implications, without exception.**
- Before editing, read the relevant source, tests, `README.md`, and `go.mod`.
- Understand the requested behavior and, when changing existing behavior, compare the branch with `main`. Distinguish branch-introduced regressions from pre-existing issues.
- Make the smallest coherent change. Do not include unrelated bug fixes, refactorings, dependency updates, or performance work; report those separately. For analysis-only requests, do not edit files or create patches unless asked.
- Follow existing naming, formatting, file organization, error handling, and option patterns. Avoid unrelated formatting changes.
- Apply SOLID pragmatically: keep responsibilities clear and abstractions justified by actual needs. Prefer readable, straightforward code (KISS before DRY); reuse existing mechanisms rather than introducing speculative interfaces or helpers.
- Keep validation close to the code responsible for the corresponding behavior. Separate static from context-dependent validation, and avoid redundant checks across layers.
- Preserve public API compatibility unless explicitly asked otherwise, including option behavior, error contracts, and serialized representations.
- Do not edit generated mocks manually or change `go.mod` / `go.sum` just to accommodate a local environment.
- Preserve the library's framework independence and its `Message` abstraction.

## RFC compliance and security

- Check protocol-related changes against the relevant RFC text, not only existing tests or behavior on `main`. Explain consequential design decisions in terms of the applicable requirement.
- Distinguish RFC compliance issues from exploitable security vulnerabilities. Evaluate concrete threat scenarios, including risks introduced by stricter validation.
- Validate before lossy conversion: preserve parameter presence, types, and values until the relevant checks are complete.
- Respect the API contracts for Structured Fields component identifiers and any supported simplified configuration syntax.
- Never relax signature, component, timestamp, nonce, algorithm, or key validation merely to satisfy tests. Assess security and compatibility implications explicitly.

## Test design

- Each unit test function should cover the meaningful positive and negative branches of its own target function or method. Higher-level tests should exercise that function's orchestration and error propagation, not duplicate detailed validation tests of its dependencies.
- When refactoring responsibilities, move the corresponding tests to the appropriate target functions and remove obsolete or overlapping scenarios.
- Extend existing test functions where possible. Add only cases for new behavior, regressions, or genuinely uncovered edges; avoid overlapping scenarios.
- Use table-driven tests only when they improve clarity. Keep cases independently understandable without unnecessary helpers or abstraction (KISS before DRY).
- Put end-to-end signing, verification, and cross-API round trips in integration tests rather than repeating entire workflows in unit tests.
- Assert observable contracts, including partial results and error identity or wrapping (`errors.Is` where appropriate), rather than incidental implementation details.
- Treat coverage as a diagnostic, not a target percentage. Inspect whether changed functions' meaningful branches have appropriate tests. Prefer removing unreachable or redundant code over adding artificial tests solely to increase coverage.
- Use `integration_test.go` for cross-API workflows and `rfc_vectors_test.go` for RFC test vectors.

## Performance

- Prioritize the common case: one signature and typically no more than ten covered components. Two or three signatures occur occasionally; many signatures or components may be attacker-controlled.
- For changes to existing hot paths, compare equivalent inputs on the branch and `main`. Measure latency, allocations, and bytes allocated across repeated runs before drawing conclusions.
- Avoid unnecessary processing of unselected signatures and pathological scaling for untrusted inputs, without weakening required parsing or validation. Do not trade simplicity for marginal or unrelated optimizations.

## Validation and delivery

- Follow the repository's formatting and `.golangci.yaml` configuration, including configured use of `gofmt`, `gofumpt`, `goimports`, and `gci`.
- Run focused tests for changed code, then, when the environment allows:

  ```sh
  go test -count=1 ./...
  go test -race -count=1 ./...
  go vet ./...
  golangci-lint run
  git diff --check
  ```

- Use the Go version and dependencies declared by the project/CI. Report any unavailable checks and the environment actually used; never claim a check passed without running it.
- Update Go documentation and the README when public behavior changes, without unrelated rewrites.
- Before handoff, review the diff for scope, compatibility, RFC implications, test ownership, and unintended edits. Summarize changes, checks performed, and remaining trade-offs.
- Use short, imperative English PR titles suited to release notes and the repository's semantic PR conventions (`.github/semantic.yml`).
- Provide incremental patches against the agreed baseline when requested. Do not commit unless explicitly asked.
