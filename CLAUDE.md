# chaosreader2026 — Iterate-Bot Project

This project uses three interlocking engineering disciplines:
1. **The Iterate-Bot Pattern:** Small, single-task 30–60 minute iterations tracked in `BACKLOG.md`, with strategic reviews every 8 iterations.
2. **Strict TDD (`RED → GREEN → REFACTOR`):** No production code without a failing test first, built as vertical tracer bullets rather than horizontal test piles.
3. **Hypothesis-Driven Debugging (Gilfoyle Method):** Falsifiable hypotheses, smallest discriminating tests, runtime evidence over speculation, and regression tests for every bug.

## Current Iteration

- Check completed iteration count: `git log --oneline --grep='\[iter-' | wc -l`
- Start next iteration branch (`iter-N-feature-name`): `./scripts/next-iteration.sh feature-name`

## How to Run a Session

1. Read `BACKLOG.md` — pick **one** Priority 1 item (30–60 min scope, zero scope creep).
2. Run `./scripts/next-iteration.sh <feature-name>` from a clean `main` branch.
3. Implement via strict vertical-slice **TDD**:
   - **RED:** Write one minimal behavioral test using synthetic packet bytes (never real user captures). Run `cargo test` and watch it fail for the expected reason.
   - **GREEN:** Write the minimal production code required to pass. Run `cargo test` and verify all tests pass with zero warnings.
   - **REFACTOR:** Clean up duplication and naming while keeping `cargo test` green.
4. Run `./scripts/check-public-safety.sh --all` and `cargo clippy --all-targets -- -D warnings`.
5. Commit with `[iter-N]` prefix (e.g., `git commit -m "[iter-1] feat: ingest pcap and pcapng frames"`), merge to `main`, and move the item to **Completed** in `BACKLOG.md`.
6. Every 8 completed iterations (`iter-8`, `iter-16`, ...): complete `STRATEGIC-REVIEW-CHECKLIST.md` before starting new feature work.

## Investigation & Debugging Discipline (Gilfoyle Method)

When diagnosing a test failure, malformed packet edge case, or discrepancy between tools (`tshark` vs. `chaosreader2026`):
1. **Separate observations, hypotheses, and unknowns.** If two tools disagree on an output, establish what the RFC/format contract specifies before changing code.
2. **State a falsifiable hypothesis** and the exact observation that would disprove it, plus a competing explanation.
3. **Run the smallest discriminating test** (minimal byte reproduction or differential check against `tshark`). Code shows a possible mechanism; runtime output proves what happened.
4. **Keep a brief evidence ledger** on non-trivial bugs: `observation → hypothesis → disproving test → result → next decision`. If three probes add no evidence, stop and challenge the underlying assumption.
5. **Lock in the fix** with a failing reproduction test before modifying production code.

## Commands

- **Test suite:** `cargo test`
- **Lint gate:** `cargo clippy --all-targets -- -D warnings`
- **Public-repo safety gate:** `./scripts/check-public-safety.sh --all`

## Hard Constraints

- **One task per iteration** (30–60 minutes; file newly discovered ideas in `BACKLOG.md` Ideas Inbox instead of scope-creeping).
- **No production code without a watched failing test first.**
- **All tests, clippy, and public-safety checks pass before commit.**
- **Zero real user captures, keys, local paths, or internal hostnames in git.** Use synthetic packet builders in tests.
- **Strategic review every 8 iterations.**
