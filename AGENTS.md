# AGENTS.md

This file provides repository-specific guidance for AI coding agents working on httpsig.

## Project context

`httpsig` implements HTTP Message Signatures (RFC 9421) and uses HTTP Structured Fields (RFC 8941, via `httpsfv`).

## Scope and design

- `httpsig` implements security related code. **Every change must be reviewed for security implications, without exception.**
- Before editing, establish the actual branch, HEAD, and working-tree state; read the relevant source, tests, `README.md`, and `go.mod`.
- Understand the requested behavior and, when changing existing behavior, compare the branch with `main`. Distinguish branch-introduced regressions from pre-existing issues.
- Make the smallest coherent change. Do not include unrelated bug fixes, refactorings, dependency updates, or performance work; report those separately. For analysis-only requests, do not edit files or create patches unless asked.
- Follow existing naming, formatting, file organization, error handling, option patterns, and local test conventions. When multiple valid approaches exist, prefer the one consistent with surrounding code. Avoid unrelated formatting changes.
- Apply SOLID pragmatically: keep responsibilities clear and abstractions justified by actual needs. Prefer readable, straightforward code (KISS before DRY); reuse existing mechanisms rather than introducing speculative interfaces or helpers.
- Keep validation close to the code responsible for the corresponding behavior. Separate static from context-dependent validation, and avoid redundant checks across layers.
- Preserve public API compatibility unless explicitly asked otherwise, including option behavior, error contracts, and serialized representations.
- Do not edit generated mocks manually or change `go.mod` / `go.sum` just to accommodate a local environment.
- Preserve the library's framework independence and its `Message` abstraction.

## RFC compliance and security

- Check protocol-related changes against the relevant RFC text, not only existing tests or behavior on `main`. Explain consequential design decisions in terms of the applicable requirement.
- When specifications are ambiguous, distinguish normative requirements from examples, check errata and the relevant versions of referenced specifications, and consult independent implementations for interoperability without treating their behavior as normative.
- Distinguish RFC compliance issues from exploitable security vulnerabilities. Evaluate concrete threat scenarios, including risks introduced by stricter validation.
- Validate before lossy conversion: preserve parameter presence, types, and values until the relevant checks are complete.
- Preserve protocol-level type distinctions across parsing, serialization, public APIs, and comparisons. When changing supported types, test round trips and assess compatibility implications.
- Review untrusted-input paths for possible panics, including unchecked type assertions, nil dereferences, and dependency behavior. Malformed protocol input should produce controlled errors.
- Respect the API contracts for Structured Fields component identifiers and any supported simplified configuration syntax.
- Never relax signature, component, timestamp, nonce, algorithm, or key validation merely to satisfy tests. Assess security and compatibility implications explicitly.

## Test design

- Each unit test function should cover the meaningful positive and negative branches of its own target function or method. Higher-level tests should exercise that function's orchestration and error propagation, not duplicate detailed validation tests of its dependencies.
- When introducing a dedicated unit test for an existing function or refactoring responsibilities, consolidate its relevant cases, including those previously tested indirectly, in the owning test. Remove obsolete or overlapping scenarios from higher-level tests.
- Extend existing test functions where possible. Add only cases for new behavior, regressions, or genuinely uncovered edges; avoid overlapping scenarios.
- Use table-driven tests when they improve clarity. Prefer one coherent table for related scenarios rather than mixing test structures unnecessarily. Keep test cases self-contained with explicit, case-specific assertions. Extract helpers only when they materially improve readability, not merely to eliminate repetition.
- When restructuring existing tests, preserve their meaningful scenarios, assertions, and error expectations. Passing tests alone do not establish that the refactoring retained equivalent coverage.
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
- Document public API behavior and contracts in GoDoc. Keep the README focused on discoverability and high-level usage rather than duplicating API documentation. Add security notes for concrete requirements or relevant limitations, not generic advice.
- Before handoff, review the diff for scope, compatibility, RFC implications, test ownership, and unintended edits. Summarize changes, checks performed, and remaining trade-offs.
- Use short, imperative English PR titles that precisely describe the actual change and suit release notes and the repository's semantic PR conventions (`.github/semantic.yml`). Keep PR descriptions concise; for non-obvious bug fixes, describe the original failure and the correction, preferably with a minimal concrete example.
- Provide incremental patches against the agreed baseline when requested. Do not commit unless explicitly asked.
